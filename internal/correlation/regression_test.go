package correlation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// drainAlerts returns every alert currently queued on the engine's alert
// channel without blocking. Tests call processEvent directly (no workers), so
// alerts accumulate in the buffered channel.
func drainAlerts(e *Engine) []*Alert {
	var out []*Alert
	for {
		select {
		case a := <-e.alertCh:
			out = append(out, a)
		default:
			return out
		}
	}
}

func testEvent(action string) *schema.Event {
	return &schema.Event{
		EventID:   uuid.New(),
		Timestamp: time.Now(),
		Source:    schema.Source{Product: "test", Host: "host-1"},
		Action:    action,
		Outcome:   schema.OutcomeSuccess,
		Severity:  3,
		Actor:     &schema.Actor{IPAddress: "10.0.0.1", ID: "user-1"},
		TenantID:  "default",
	}
}

func mustAddRule(t *testing.T, e *Engine, rule *Rule) {
	t.Helper()
	if err := e.AddRule(rule); err != nil {
		t.Fatalf("AddRule(%s): %v", rule.ID, err)
	}
}

// Regression (H02/R05): the filter of every shipped detection rule lives in
// EventConditions (or Condition), which the engine never evaluated, so each
// rule fired on every event.
func TestEngine_RuleFiltersAreEvaluated(t *testing.T) {
	threshold := &ThresholdConfig{Count: 1, Operator: "gte"}
	tests := []struct {
		name       string
		rule       *Rule
		event      *schema.Event
		wantAlerts int
	}{
		{
			name: "event_conditions: unrelated event does not fire",
			rule: &Rule{EventConditions: []Condition{
				{Field: "action", Operator: "eq", Value: "key.export"},
			}},
			event:      testEvent("user.login"),
			wantAlerts: 0,
		},
		{
			name: "event_conditions: matching event fires",
			rule: &Rule{EventConditions: []Condition{
				{Field: "action", Operator: "eq", Value: "key.export"},
			}},
			event:      testEvent("key.export"),
			wantAlerts: 1,
		},
		{
			name: "event_conditions: all conditions must match",
			rule: &Rule{EventConditions: []Condition{
				{Field: "action", Operator: "eq", Value: "key.export"},
				{Field: "outcome", Operator: "eq", Value: "failure"},
			}},
			event:      testEvent("key.export"), // outcome=success
			wantAlerts: 0,
		},
		{
			name: "event_conditions: in operator with values",
			rule: &Rule{EventConditions: []Condition{
				{Field: "action", Operator: "in", Values: []string{"key.access", "key.sign"}},
			}},
			event:      testEvent("user.login"),
			wantAlerts: 0,
		},
		{
			name: "condition tree: or group without match does not fire",
			rule: &Rule{Condition: Condition{Or: []Condition{
				{Field: "action", Operator: "eq", Value: "a"},
				{Field: "action", Operator: "eq", Value: "b"},
			}}},
			event:      testEvent("user.login"),
			wantAlerts: 0,
		},
		{
			name: "condition tree: or group match fires",
			rule: &Rule{Condition: Condition{Or: []Condition{
				{Field: "action", Operator: "eq", Value: "a"},
				{Field: "action", Operator: "eq", Value: "user.login"},
			}}},
			event:      testEvent("user.login"),
			wantAlerts: 1,
		},
		{
			name: "conditions.match and event_conditions are both applied",
			rule: &Rule{
				Conditions: Conditions{Match: []MatchCondition{
					{Field: "action", Operator: "eq", Value: "user.login"},
				}},
				EventConditions: []Condition{
					{Field: "outcome", Operator: "eq", Value: "failure"},
				},
			},
			event:      testEvent("user.login"),
			wantAlerts: 0,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEngine(DefaultEngineConfig())
			rule := tt.rule
			rule.ID = fmt.Sprintf("filter-%d", i)
			rule.Name = tt.name
			rule.Type = RuleTypeThreshold
			rule.Enabled = true
			rule.Severity = 5
			rule.Window = time.Minute
			rule.Threshold = threshold
			mustAddRule(t, e, rule)

			e.processEvent(context.Background(), tt.event)

			if got := len(drainAlerts(e)); got != tt.wantAlerts {
				t.Errorf("alerts = %d, want %d", got, tt.wantAlerts)
			}
		})
	}
}

// Regression (R05): synthetic alert.fired events re-injected for chaining must
// only reach rules that consume alerts; otherwise every alert re-triggers
// loosely filtered rules and the engine amplifies a single event.
func TestEngine_SyntheticAlertEventsOnlyReachAlertConsumers(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	loose := &Rule{
		ID: "loose", Name: "any high severity event", Type: RuleTypeThreshold,
		Enabled: true, Severity: 5, Window: time.Minute,
		EventConditions: []Condition{{Field: "severity", Operator: "gte", Value: 1}},
		GroupBy:         []string{"metadata.alert_id"},
		Threshold:       &ThresholdConfig{Count: 1, Operator: "gte"},
	}
	mustAddRule(t, e, loose)

	NewAlertReinjector(e).Reinject(&Alert{
		ID: uuid.New(), RuleID: "some-rule", RuleName: "Some Rule",
		Severity: 7, Timestamp: time.Now(), GroupKey: "default",
	})
	synthetic := <-e.eventCh
	e.processEvent(context.Background(), synthetic)

	if got := len(drainAlerts(e)); got != 0 {
		t.Errorf("synthetic alert.fired event triggered %d alert(s) on a rule that does not consume alerts", got)
	}
}

// Regression (H06): windows were tumbling; a burst straddling the reset point
// was never counted even though the last Window held Count events.
func TestEngine_ThresholdWindowSlides(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	mustAddRule(t, e, &Rule{
		ID: "sliding", Name: "sliding", Type: RuleTypeThreshold, Enabled: true,
		Severity: 5, Window: 600 * time.Millisecond,
		EventConditions: []Condition{{Field: "action", Operator: "eq", Value: "auth.failure"}},
		Threshold:       &ThresholdConfig{Count: 5, Operator: "gte"},
	})
	ctx := context.Background()

	e.processEvent(ctx, testEvent("auth.failure")) // t=0 opens the window
	time.Sleep(400 * time.Millisecond)
	for i := 0; i < 3; i++ { // t≈400ms
		e.processEvent(ctx, testEvent("auth.failure"))
	}
	time.Sleep(300 * time.Millisecond)
	for i := 0; i < 2; i++ { // t≈700ms: the last 600ms hold 5 events
		e.processEvent(ctx, testEvent("auth.failure"))
	}

	if got := len(drainAlerts(e)); got != 1 {
		t.Errorf("alerts = %d, want 1 (5 events within the last window)", got)
	}
}

// Regression (H07): trimming compared event timestamps with the wall clock, so
// events delivered late (backlog, clock skew) never accumulated.
func TestEngine_LateEventsAccumulate(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	mustAddRule(t, e, &Rule{
		ID: "late", Name: "late", Type: RuleTypeThreshold, Enabled: true,
		Severity: 5, Window: time.Minute,
		EventConditions: []Condition{{Field: "action", Operator: "eq", Value: "auth.failure"}},
		GroupBy:         []string{"actor.ip"},
		Threshold:       &ThresholdConfig{Count: 3, Operator: "gte"},
	})

	for i := 0; i < 10; i++ {
		ev := testEvent("auth.failure")
		ev.Timestamp = time.Now().Add(-10*time.Minute + time.Duration(i)*time.Second)
		e.processEvent(context.Background(), ev)
	}

	if got := len(drainAlerts(e)); got != 1 {
		t.Errorf("alerts = %d, want 1 (10 failures arrived within the window)", got)
	}
}

// Regression (H14): EngineConfig.DedupWindow was ignored.
func TestEngine_DedupWindowIsHonoured(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.DedupWindow = time.Hour
	e := NewEngine(cfg)
	mustAddRule(t, e, &Rule{
		ID: "dedup", Name: "dedup", Type: RuleTypeThreshold, Enabled: true,
		Severity: 5, Window: 100 * time.Millisecond,
		EventConditions: []Condition{{Field: "action", Operator: "eq", Value: "x.y"}},
		Threshold:       &ThresholdConfig{Count: 1, Operator: "gte"},
	})

	e.processEvent(context.Background(), testEvent("x.y"))
	time.Sleep(150 * time.Millisecond) // past the rule window, inside DedupWindow
	e.processEvent(context.Background(), testEvent("x.y"))

	if got := len(drainAlerts(e)); got != 1 {
		t.Errorf("alerts = %d, want 1 (second alert is inside DedupWindow)", got)
	}
}

// Regression (H10, H11): ordered sequences could not skip optional steps and
// stalled when the same conditions appeared in more than one step.
func TestEngine_OrderedSequence(t *testing.T) {
	step := func(name, action string, required bool) SequenceStep {
		return SequenceStep{
			Name:       name,
			Conditions: []Condition{{Field: "action", Operator: "eq", Value: action}},
			Required:   required,
		}
	}
	tests := []struct {
		name       string
		steps      []SequenceStep
		events     []string
		wantAlerts int
	}{
		{
			name:       "optional middle step skipped",
			steps:      []SequenceStep{step("a", "a.a", true), step("b", "b.b", false), step("c", "c.c", true)},
			events:     []string{"a.a", "c.c"},
			wantAlerts: 1,
		},
		{
			name:       "optional middle step present",
			steps:      []SequenceStep{step("a", "a.a", true), step("b", "b.b", false), step("c", "c.c", true)},
			events:     []string{"a.a", "b.b", "c.c"},
			wantAlerts: 1,
		},
		{
			name:       "repeated step conditions advance",
			steps:      []SequenceStep{step("f1", "auth.failure", false), step("f2", "auth.failure", false), step("s", "auth.success", false)},
			events:     []string{"auth.failure", "auth.failure", "auth.success"},
			wantAlerts: 1,
		},
		{
			name:       "out of order does not fire",
			steps:      []SequenceStep{step("a", "a.a", true), step("c", "c.c", true)},
			events:     []string{"c.c", "a.a"},
			wantAlerts: 0,
		},
		{
			name:       "required step cannot be skipped",
			steps:      []SequenceStep{step("a", "a.a", true), step("b", "b.b", true), step("c", "c.c", true)},
			events:     []string{"a.a", "c.c"},
			wantAlerts: 0,
		},
		{
			name:       "completed sequence is consumed",
			steps:      []SequenceStep{step("a", "a.a", true), step("b", "b.b", true)},
			events:     []string{"a.a", "b.b", "b.b"},
			wantAlerts: 1,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEngine(DefaultEngineConfig())
			mustAddRule(t, e, &Rule{
				ID: fmt.Sprintf("seq-%d", i), Name: tt.name, Type: RuleTypeSequence,
				Enabled: true, Severity: 5, Window: time.Minute,
				Sequence: &SequenceConfig{Ordered: true, Steps: tt.steps},
			})
			for _, action := range tt.events {
				e.processEvent(context.Background(), testEvent(action))
			}
			if got := len(drainAlerts(e)); got != tt.wantAlerts {
				t.Errorf("alerts = %d, want %d", got, tt.wantAlerts)
			}
		})
	}
}

// Regression (H06): the sequence MaxSpan was never enforced; steps further
// apart than MaxSpan still completed the sequence.
func TestEngine_SequenceMaxSpan(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	mustAddRule(t, e, &Rule{
		ID: "span", Name: "span", Type: RuleTypeSequence, Enabled: true,
		Severity: 5, Window: time.Minute,
		Sequence: &SequenceConfig{
			Ordered: true,
			MaxSpan: 100 * time.Millisecond,
			Steps: []SequenceStep{
				{Name: "a", Conditions: []Condition{{Field: "action", Operator: "eq", Value: "a.a"}}},
				{Name: "b", Conditions: []Condition{{Field: "action", Operator: "eq", Value: "b.b"}}},
			},
		},
	})
	e.processEvent(context.Background(), testEvent("a.a"))
	time.Sleep(150 * time.Millisecond)
	e.processEvent(context.Background(), testEvent("b.b"))

	if got := len(drainAlerts(e)); got != 0 {
		t.Errorf("alerts = %d, want 0 (steps were further apart than max_span)", got)
	}
}

func heartbeatAbsenceRule(groupBy []string, window time.Duration) *Rule {
	return &Rule{
		ID: "heartbeat-absent", Name: "Heartbeat missing", Type: RuleTypeAbsence,
		Enabled: true, Severity: 7, Window: window, GroupBy: groupBy,
		Absence: &AbsenceConfig{ExpectedConditions: []Condition{
			{Field: "action", Operator: "eq", Value: "system.heartbeat"},
		}},
	}
}

// Regression (H08, H09): absence rules treated any event as the expected one,
// and fired immediately at startup before a heartbeat could have arrived.
func TestEngine_AbsenceUsesExpectedConditions(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	mustAddRule(t, e, heartbeatAbsenceRule(nil, 200*time.Millisecond))

	// Startup: nothing is overdue yet.
	e.checkAbsenceRules()
	if got := len(drainAlerts(e)); got != 0 {
		t.Errorf("absence rule fired %d alert(s) at startup, before a full period elapsed", got)
	}

	// Unrelated traffic must not count as the heartbeat.
	for i := 0; i < 5; i++ {
		e.processEvent(context.Background(), testEvent("user.login"))
	}
	time.Sleep(250 * time.Millisecond)
	e.checkAbsenceRules()
	if got := len(drainAlerts(e)); got != 1 {
		t.Errorf("alerts = %d, want 1 (heartbeat absent for a full period)", got)
	}
}

// Regression (H09): with GroupBy set, a synthetic "default" group that no event
// can ever reach fired every period even though every host reported.
func TestEngine_AbsenceGroupByNoPlaceholderGroup(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	mustAddRule(t, e, heartbeatAbsenceRule([]string{"source.host"}, 150*time.Millisecond))

	e.checkAbsenceRules() // the checker ticks before the first heartbeat arrives
	for period := 0; period < 4; period++ {
		hb := testEvent("system.heartbeat")
		hb.Source.Host = "db1"
		e.processEvent(context.Background(), hb)
		time.Sleep(160 * time.Millisecond)
		e.checkAbsenceRules()
	}

	alerts := drainAlerts(e)
	if len(alerts) != 0 {
		keys := make([]string, 0, len(alerts))
		for _, a := range alerts {
			keys = append(keys, a.GroupKey)
		}
		t.Errorf("host db1 reported every period but %d absence alert(s) fired, group keys %v", len(alerts), keys)
	}
}

// Regression (H09 positive case): a group that stops reporting is detected.
func TestEngine_AbsenceGroupStopsReporting(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	mustAddRule(t, e, heartbeatAbsenceRule([]string{"source.host"}, 100*time.Millisecond))

	hb := testEvent("system.heartbeat")
	hb.Source.Host = "db1"
	e.processEvent(context.Background(), hb)
	time.Sleep(120 * time.Millisecond)
	e.checkAbsenceRules() // period 1: heartbeat seen
	time.Sleep(120 * time.Millisecond)
	e.checkAbsenceRules() // period 2: nothing

	alerts := drainAlerts(e)
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(alerts))
	}
	if want := "[source.host=db1]"; alerts[0].GroupKey != want {
		t.Errorf("group key = %q, want %q", alerts[0].GroupKey, want)
	}
}

// Regression (H15): every threshold evaluation stored a baseline sample, even
// for rules without a Baseline config, and nothing ever freed them.
func TestEngine_BaselineOnlyRecordedForBaselineRules(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	rule := &Rule{
		ID: "no-baseline", Name: "no baseline", Type: RuleTypeThreshold, Enabled: true,
		Severity: 5, Window: time.Minute,
		EventConditions: []Condition{{Field: "action", Operator: "eq", Value: "x.y"}},
		Threshold:       &ThresholdConfig{Count: 1000000, Operator: "gte"},
	}
	mustAddRule(t, e, rule)
	for i := 0; i < 500; i++ {
		e.processEvent(context.Background(), testEvent("x.y"))
	}
	if stats := e.baseline.Stats(rule.ID, "default", "event_count", Baseline7d); stats != nil {
		t.Errorf("baseline retained %d samples for a rule without a baseline config", stats.Samples)
	}
}

// Regression (H16): the adaptive threshold was truncated with int(), so a
// learned threshold of 1.5 became 1 and every single event fired, overriding
// the static threshold.
func TestEngine_AdaptiveThresholdNotTruncated(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	e.baseline.started = time.Now().Add(-30 * 24 * time.Hour) // past warmup
	rule := &Rule{
		ID: "adaptive", Name: "adaptive", Type: RuleTypeThreshold, Enabled: true,
		Severity: 5, Window: time.Minute,
		EventConditions: []Condition{{Field: "action", Operator: "eq", Value: "x.y"}},
		Threshold:       &ThresholdConfig{Count: 10, Operator: "gte"},
		Baseline: &BaselineConfig{
			Metric: "event_count", Window: Baseline1h, Multiplier: 1.5,
			Percentile: "p95", MinSamples: 10, WarmupDays: 1,
		},
	}
	mustAddRule(t, e, rule)
	for i := 0; i < 100; i++ {
		e.baseline.Record(rule.ID, "default", "event_count", 1)
	}

	e.processEvent(context.Background(), testEvent("x.y"))
	e.processEvent(context.Background(), testEvent("x.y"))

	if got := len(drainAlerts(e)); got != 0 {
		t.Errorf("alerts = %d, want 0 (2 events, static threshold 10, learned 1.5)", got)
	}
}
