package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// E2E round 2: with the shipped dedup_window (15m) the engine dropped every
// firing of a rule and group within 15 minutes of its alert, before the
// alert manager could merge it into the open alert or raise a new alert
// after the old one was resolved. Firings within the dedup window are now
// sent as recurrences, each listing only events no earlier alert reported.

func singleEventRule(id string) *Rule {
	return &Rule{
		ID: id, Name: id, Type: RuleTypeThreshold, Enabled: true,
		Severity: 9, Window: time.Hour,
		EventConditions: []Condition{{Field: "action", Operator: "eq", Value: "key.export"}},
		GroupBy:         []string{"target"},
		Threshold:       &ThresholdConfig{Count: 1, Operator: "gte"},
	}
}

func eventIDs(a *Alert) []uuid.UUID {
	ids := make([]uuid.UUID, len(a.Events))
	for i, e := range a.Events {
		ids[i] = e.EventID
	}
	return ids
}

func TestEngine_FiringWithinDedupWindowIsSentAsRecurrence(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.DedupWindow = 15 * time.Minute // the shipped configuration
	cfg.RecurrenceInterval = 50 * time.Millisecond
	e := NewEngine(cfg)
	mustAddRule(t, e, singleEventRule("export"))

	first := testEvent("key.export")
	first.Target = "rk-1"
	e.processEvent(context.Background(), first)
	alerts := drainAlerts(e)
	if len(alerts) != 1 || alerts[0].Recurrence {
		t.Fatalf("first firing = %+v, want one new alert", alerts)
	}

	time.Sleep(60 * time.Millisecond) // past RecurrenceInterval, inside DedupWindow
	again := testEvent("key.export")
	again.Target = "rk-1"
	e.processEvent(context.Background(), again)
	alerts = drainAlerts(e)
	if len(alerts) != 1 {
		t.Fatalf("firing inside the dedup window sent %d alerts, want 1 recurrence (it was dropped)", len(alerts))
	}
	rec := alerts[0]
	if !rec.Recurrence || rec.RuleID != "export" || rec.GroupKey != "[target=rk-1]" {
		t.Errorf("recurrence = %+v, want a recurrence of export for [target=rk-1]", rec)
	}
	if ids := eventIDs(rec); len(ids) != 1 || ids[0] != again.EventID {
		t.Errorf("recurrence events = %v, want only the new event %s (the first was already reported)", ids, again.EventID)
	}
}

func TestEngine_RecurrencesAreBatchedPerInterval(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.DedupWindow = time.Hour
	cfg.RecurrenceInterval = time.Hour
	e := NewEngine(cfg)
	rule := validThresholdRule()
	rule.Threshold.Count = 3
	mustAddRule(t, e, &rule)

	var sent []uuid.UUID
	for i := 0; i < 7; i++ {
		ev := testEvent("auth.failure")
		sent = append(sent, ev.EventID)
		e.processEvent(context.Background(), ev)
	}
	alerts := drainAlerts(e)
	if len(alerts) != 1 || alerts[0].Recurrence || len(alerts[0].Events) != 3 {
		t.Fatalf("alerts = %d, want one new alert with the 3 events that crossed the threshold", len(alerts))
	}

	// The 4 later firings wait for the interval, then go out as one.
	e.flushRecurrences(time.Now())
	if got := drainAlerts(e); len(got) != 0 {
		t.Fatalf("flush inside the interval sent %d alerts", len(got))
	}
	e.flushRecurrences(time.Now().Add(2 * time.Hour))
	recs := drainAlerts(e)
	if len(recs) != 1 || !recs[0].Recurrence {
		t.Fatalf("flush after the interval = %+v, want one recurrence", recs)
	}

	seen := map[uuid.UUID]int{}
	for _, a := range append(alerts, recs...) {
		for _, id := range eventIDs(a) {
			seen[id]++
		}
	}
	for _, id := range sent {
		if seen[id] != 1 {
			t.Errorf("event %s reported %d times, want exactly once", id, seen[id])
		}
	}
	if len(seen) != len(sent) {
		t.Errorf("reported %d distinct events, want %d", len(seen), len(sent))
	}

	// Nothing is left to send.
	e.flushRecurrences(time.Now().Add(4 * time.Hour))
	if got := drainAlerts(e); len(got) != 0 {
		t.Errorf("second flush sent %d alerts", len(got))
	}
}

// E2E round 2: a new alert raised after the dedup window listed the events
// an earlier alert had already reported (event_count 2 for one new event).
func TestEngine_NewAlertListsOnlyUnreportedEvents(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.DedupWindow = time.Nanosecond // every firing is a new alert
	e := NewEngine(cfg)
	mustAddRule(t, e, singleEventRule("export"))

	var want []uuid.UUID
	for i := 0; i < 3; i++ {
		ev := testEvent("key.export")
		ev.Target = "rk-2"
		want = append(want, ev.EventID)
		e.processEvent(context.Background(), ev)
		time.Sleep(time.Millisecond)
	}
	alerts := drainAlerts(e)
	if len(alerts) != 3 {
		t.Fatalf("alerts = %d, want 3", len(alerts))
	}
	for i, a := range alerts {
		if a.Recurrence {
			t.Errorf("alert %d is a recurrence outside the dedup window", i)
		}
		if ids := eventIDs(a); len(ids) != 1 || ids[0] != want[i] {
			t.Errorf("alert %d events = %v, want only %s", i, ids, want[i])
		}
	}
}

// A new alert after the dedup window takes over a recurrence still waiting
// for its interval, so those events are not lost.
func TestEngine_NewAlertTakesOverPendingRecurrence(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.DedupWindow = 40 * time.Millisecond
	cfg.RecurrenceInterval = time.Hour
	e := NewEngine(cfg)
	mustAddRule(t, e, singleEventRule("export"))

	var sent []uuid.UUID
	for i := 0; i < 2; i++ {
		ev := testEvent("key.export")
		ev.Target = "rk-3"
		sent = append(sent, ev.EventID)
		e.processEvent(context.Background(), ev)
	}
	if got := drainAlerts(e); len(got) != 1 {
		t.Fatalf("alerts = %d, want 1 (the second firing waits)", len(got))
	}
	time.Sleep(50 * time.Millisecond)
	last := testEvent("key.export")
	last.Target = "rk-3"
	e.processEvent(context.Background(), last)
	alerts := drainAlerts(e)
	if len(alerts) != 1 || alerts[0].Recurrence {
		t.Fatalf("alerts after the dedup window = %+v, want one new alert", alerts)
	}
	if ids := eventIDs(alerts[0]); len(ids) != 2 || ids[0] != sent[1] || ids[1] != last.EventID {
		t.Errorf("new alert events = %v, want the waiting %s and the new %s", ids, sent[1], last.EventID)
	}
	e.flushRecurrences(time.Now().Add(2 * time.Hour))
	if got := drainAlerts(e); len(got) != 0 {
		t.Errorf("flush sent %d alerts, want none left", len(got))
	}
}

// The flusher started by Start sends a waiting recurrence on its own.
func TestEngine_StartFlushesRecurrences(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.DedupWindow = time.Hour
	cfg.RecurrenceInterval = 30 * time.Millisecond
	cfg.WorkerCount = 1
	e := NewEngine(cfg)
	mustAddRule(t, e, singleEventRule("export"))
	got := make(chan *Alert, 10)
	e.AddHandler(func(_ context.Context, a *Alert) error {
		got <- a
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Start(ctx)
	defer e.Stop()

	for i := 0; i < 2; i++ {
		ev := testEvent("key.export")
		ev.Target = "rk-4"
		e.ProcessEvent(ev)
	}
	timeout := time.After(5 * time.Second)
	for _, wantRecurrence := range []bool{false, true} {
		select {
		case a := <-got:
			if a.Recurrence != wantRecurrence || len(a.Events) != 1 {
				t.Errorf("alert recurrence=%v events=%d, want recurrence=%v with 1 event", a.Recurrence, len(a.Events), wantRecurrence)
			}
		case <-timeout:
			t.Fatalf("no alert (want recurrence=%v)", wantRecurrence)
		}
	}
}

// Recurrences are not re-injected: chain rules see one alert.fired event
// per dedup window, as before.
func TestReinjector_SkipsRecurrences(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	r := NewAlertReinjector(e)
	r.Reinject(&Alert{ID: uuid.New(), RuleID: "x", Recurrence: true})
	if n := len(e.eventCh); n != 0 {
		t.Errorf("re-injected %d events for a recurrence, want 0", n)
	}
	r.Reinject(&Alert{ID: uuid.New(), RuleID: "x"})
	if n := len(e.eventCh); n != 1 {
		t.Errorf("re-injected %d events for a new alert, want 1", n)
	}
}

// An absence rule whose expected event stays missing reports each further
// period within the dedup window as a recurrence (it used to be dropped, so
// a resolved absence alert never came back while the source stayed silent).
func TestEngine_AbsenceWithinDedupWindowIsSentAsRecurrence(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.DedupWindow = time.Hour
	cfg.RecurrenceInterval = time.Millisecond
	e := NewEngine(cfg)
	mustAddRule(t, e, heartbeatAbsenceRule([]string{"source.host"}, 60*time.Millisecond))

	hb := testEvent("system.heartbeat")
	hb.Source.Host = "db1"
	e.processEvent(context.Background(), hb)
	time.Sleep(70 * time.Millisecond)
	e.checkAbsenceRules() // period 1: heartbeat seen

	var got []bool
	for range 2 {
		time.Sleep(70 * time.Millisecond)
		e.checkAbsenceRules() // heartbeat missing
		for _, a := range drainAlerts(e) {
			if a.GroupKey != "[source.host=db1]" || len(a.Events) != 0 {
				t.Errorf("absence alert group=%q events=%d, want [source.host=db1] with none", a.GroupKey, len(a.Events))
			}
			got = append(got, a.Recurrence)
		}
	}
	if len(got) != 2 || got[0] || !got[1] {
		t.Errorf("absence alerts recurrence flags = %v, want [false true] (a new alert, then a recurrence)", got)
	}
}
