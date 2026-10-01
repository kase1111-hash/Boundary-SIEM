package alerting

import (
	"context"
	"testing"
	"time"

	"boundary-siem/internal/correlation"

	"github.com/google/uuid"
)

// E2E round 1: after an analyst resolved an alert, the same attack resuming
// within the deduplication window was dropped (logged at debug), so nothing
// told the analyst; a recurrence of an open alert did not even update its
// event count.

func TestRecurrenceAfterResolveRaisesNewAlert(t *testing.T) {
	mgr := NewManager(ManagerConfig{DeduplicationWindow: time.Hour, RetentionPeriod: time.Hour, MaxAlerts: 100}, nil)
	ch := newMockChannel("test")
	mgr.AddChannel(ch)
	ctx := context.Background()

	first := makeCorrelationAlert("sec-004", "[actor.ip=198.51.100.4]", "Auth failures", 7)
	if err := mgr.HandleCorrelationAlert(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ResolveAlert(ctx, first.ID, "analyst"); err != nil {
		t.Fatal(err)
	}

	again := makeCorrelationAlert("sec-004", "[actor.ip=198.51.100.4]", "Auth failures", 7)
	if err := mgr.HandleCorrelationAlert(ctx, again); err != nil {
		t.Fatal(err)
	}
	got, err := mgr.GetAlert(ctx, again.ID)
	if err != nil {
		t.Fatalf("recurrence after resolve raised no alert: %v", err)
	}
	if got.Status != StatusNew {
		t.Errorf("new alert status = %s, want new", got.Status)
	}
	if old, _ := mgr.GetAlert(ctx, first.ID); old.Status != StatusResolved || old.EventCount != 1 {
		t.Errorf("resolved alert changed: %+v", old)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(ch.getSentAlerts()); n != 2 {
		t.Errorf("notifications = %d, want 2 (the resumed attack is notified)", n)
	}
}

func TestRecurrenceOfOpenAlertIsMerged(t *testing.T) {
	mgr := NewManager(ManagerConfig{DeduplicationWindow: time.Hour, RetentionPeriod: time.Hour, MaxAlerts: 100}, nil)
	ch := newMockChannel("test")
	mgr.AddChannel(ch)
	ctx := context.Background()

	first := makeCorrelationAlert("sec-004", "g", "Auth failures", 7)
	if err := mgr.HandleCorrelationAlert(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := mgr.AcknowledgeAlert(ctx, first.ID, "analyst"); err != nil {
		t.Fatal(err)
	}
	before, _ := mgr.GetAlert(ctx, first.ID)

	again := makeCorrelationAlert("sec-004", "g", "Auth failures", 7)
	again.Events = append(again.Events, again.Events[0])
	again.Events[1].EventID = uuid.New()
	if err := mgr.HandleCorrelationAlert(ctx, again); err != nil {
		t.Fatal(err)
	}

	if _, err := mgr.GetAlert(ctx, again.ID); err == nil {
		t.Error("recurrence of an open alert raised a second alert")
	}
	got, _ := mgr.GetAlert(ctx, first.ID)
	if got.EventCount != 3 || len(got.EventIDs) != 3 || got.EventIDs[2] != again.Events[1].EventID {
		t.Errorf("merged alert events = %d %v, want 3 including the recurrence's", got.EventCount, got.EventIDs)
	}
	if got.Metadata[metaOccurrences] != 2 || got.Metadata[metaLastOccurrence] == nil {
		t.Errorf("merged alert metadata = %v, want occurrences 2 and last_occurrence", got.Metadata)
	}
	if !got.UpdatedAt.After(before.UpdatedAt) || got.Status != StatusAcknowledged {
		t.Errorf("merged alert = %+v, want updated_at advanced and status kept", got)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(ch.getSentAlerts()); n != 1 {
		t.Errorf("notifications = %d, want 1 (a merged recurrence is not re-notified)", n)
	}
}

// E2E round 1: the dashboard read total_alerts and open, which the stats
// endpoint never returned, so both cards showed 0.
func TestStatsReportOpenAlerts(t *testing.T) {
	mgr := NewManager(ManagerConfig{DeduplicationWindow: time.Hour, RetentionPeriod: time.Hour, MaxAlerts: 100}, nil)
	ctx := context.Background()
	var ids []uuid.UUID
	for i := 0; i < 4; i++ {
		a := makeCorrelationAlert("r", string(rune('a'+i)), "x", 5)
		if err := mgr.HandleCorrelationAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, a.ID)
	}
	if err := mgr.AcknowledgeAlert(ctx, ids[1], "u"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ResolveAlert(ctx, ids[2], "u"); err != nil {
		t.Fatal(err)
	}
	stats := mgr.Stats()
	if stats["total"] != 4 || stats["open"] != 3 {
		t.Errorf("stats = %v, want total 4 and open 3 (new + acknowledged)", stats)
	}
}

// The resolved state survives a restart: LoadFromDB seeds deduplication with
// the alert, and a recurrence raises a new alert instead of being dropped.
func TestRecurrenceAfterResolveAcrossRestartClickHouse(t *testing.T) {
	db := openTestClickHouse(t)
	ctx := context.Background()

	before := NewManager(DefaultManagerConfig(), db)
	first := makeCorrelationAlert("sec-004", "[actor.ip=198.51.100.4]", "Auth failures", 7)
	if err := before.HandleCorrelationAlert(ctx, first); err != nil {
		t.Fatal(err)
	}
	open := makeCorrelationAlert("sec-009", "[actor.ip=198.51.100.5]", "SSH brute force", 7)
	if err := before.HandleCorrelationAlert(ctx, open); err != nil {
		t.Fatal(err)
	}
	if err := before.ResolveAlert(ctx, first.ID, "analyst"); err != nil {
		t.Fatal(err)
	}

	after := NewManager(DefaultManagerConfig(), db)
	if _, err := after.LoadFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	again := makeCorrelationAlert("sec-004", "[actor.ip=198.51.100.4]", "Auth failures", 7)
	if err := after.HandleCorrelationAlert(ctx, again); err != nil {
		t.Fatal(err)
	}
	if _, err := after.GetAlert(ctx, again.ID); err != nil {
		t.Errorf("recurrence of a resolved alert after restart raised no alert: %v", err)
	}

	// The open one still merges, and the merge is persisted.
	openAgain := makeCorrelationAlert("sec-009", "[actor.ip=198.51.100.5]", "SSH brute force", 7)
	if err := after.HandleCorrelationAlert(ctx, openAgain); err != nil {
		t.Fatal(err)
	}
	reloaded := NewManager(DefaultManagerConfig(), db)
	got, err := reloaded.GetAlert(ctx, open.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EventCount != 2 {
		t.Errorf("persisted event_count after a merged recurrence = %d, want 2", got.EventCount)
	}
}

// E2E round 2: merging a recurrence added all of its events, including ones
// the alert already listed (event_count 3 with 2 distinct event IDs).
func TestMergedRecurrenceDoesNotCountKnownEvents(t *testing.T) {
	mgr := NewManager(ManagerConfig{DeduplicationWindow: time.Hour, RetentionPeriod: time.Hour, MaxAlerts: 100}, nil)
	ctx := context.Background()

	first := makeCorrelationAlert("sec-001", "[actor.ip=10.78.0.3]", "Blocked RPC", 9)
	if err := mgr.HandleCorrelationAlert(ctx, first); err != nil {
		t.Fatal(err)
	}
	again := makeCorrelationAlert("sec-001", "[actor.ip=10.78.0.3]", "Blocked RPC", 9)
	again.Recurrence = true
	newEvent := again.Events[0]
	again.Events = []correlation.EventRef{first.Events[0], newEvent}
	if err := mgr.HandleCorrelationAlert(ctx, again); err != nil {
		t.Fatal(err)
	}

	got, err := mgr.GetAlert(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EventCount != 2 || len(got.EventIDs) != 2 || got.EventIDs[1] != newEvent.EventID {
		t.Errorf("merged alert event_count=%d event_ids=%v, want 2 distinct events", got.EventCount, got.EventIDs)
	}
	if got.Metadata[metaOccurrences] != 2 {
		t.Errorf("occurrences = %v, want 2", got.Metadata[metaOccurrences])
	}
}
