package alerting

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// waitForSends polls until every channel has received at least want[name]
// alerts or the deadline passes, then gives stray goroutines a moment to
// deliver extra (unexpected) notifications before returning the counts.
func waitForSends(t *testing.T, channels map[string]*mockChannel, want map[string]int) map[string]int {
	t.Helper()
	counts := func() map[string]int {
		got := make(map[string]int, len(channels))
		for name, ch := range channels {
			got[name] = len(ch.getSentAlerts())
		}
		return got
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		done := true
		got := counts()
		for name, n := range want {
			if got[name] < n {
				done = false
			}
		}
		if done {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	return counts()
}

// TestEscalationTrackingIsPerPolicy is a regression test for escalation
// tracking being keyed only by (alert, rule index): when two policies match
// the same alert, the first policy's step 0 marked "step 0 escalated" for the
// alert and silently suppressed the second policy's step 0.
func TestEscalationTrackingIsPerPolicy(t *testing.T) {
	tests := []struct {
		name     string
		policies []EscalationPolicy
		checks   int
		want     map[string]int
	}{
		{
			name: "two policies share rule index 0",
			policies: []EscalationPolicy{
				{ID: "p1", Name: "oncall", Enabled: true, Rules: []EscalationRule{{After: 10 * time.Minute, Channels: []string{"oncall"}}}},
				{ID: "p2", Name: "security", Enabled: true, Rules: []EscalationRule{{After: 15 * time.Minute, Channels: []string{"security-team"}}}},
			},
			checks: 1,
			want:   map[string]int{"oncall": 1, "security-team": 1},
		},
		{
			name: "repeated checks escalate each policy step once",
			policies: []EscalationPolicy{
				{ID: "p1", Name: "oncall", Enabled: true, Rules: []EscalationRule{
					{After: 5 * time.Minute, Channels: []string{"oncall"}},
					{After: 10 * time.Minute, Channels: []string{"oncall"}},
				}},
				{ID: "p2", Name: "security", Enabled: true, Rules: []EscalationRule{{After: 15 * time.Minute, Channels: []string{"security-team"}}}},
			},
			checks: 3,
			want:   map[string]int{"oncall": 2, "security-team": 1},
		},
		{
			name: "policies without IDs are tracked separately",
			policies: []EscalationPolicy{
				{Name: "a", Enabled: true, Rules: []EscalationRule{{After: time.Minute, Channels: []string{"oncall"}}}},
				{Name: "b", Enabled: true, Rules: []EscalationRule{{After: time.Minute, Channels: []string{"security-team"}}}},
			},
			checks: 2,
			want:   map[string]int{"oncall": 1, "security-team": 1},
		},
		{
			name: "rule not yet due is not escalated",
			policies: []EscalationPolicy{
				{ID: "p1", Name: "oncall", Enabled: true, Rules: []EscalationRule{{After: 10 * time.Minute, Channels: []string{"oncall"}}}},
				{ID: "p2", Name: "security", Enabled: true, Rules: []EscalationRule{{After: time.Hour, Channels: []string{"security-team"}}}},
			},
			checks: 1,
			want:   map[string]int{"oncall": 1, "security-team": 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mgr := NewManager(DefaultManagerConfig(), nil)
			engine := NewEscalationEngine(mgr)

			channels := map[string]*mockChannel{
				"oncall":        newMockChannel("oncall"),
				"security-team": newMockChannel("security-team"),
			}
			for _, ch := range channels {
				engine.RegisterChannel(ch)
			}
			for _, p := range tt.policies {
				engine.AddPolicy(p)
			}

			corrAlert := makeCorrelationAlert("esc-rule", "esc-group", "Escalation Test", 9)
			corrAlert.Timestamp = time.Now().Add(-20 * time.Minute)
			if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
				t.Fatalf("HandleCorrelationAlert failed: %v", err)
			}

			for i := 0; i < tt.checks; i++ {
				engine.checkEscalations(ctx)
			}

			got := waitForSends(t, channels, tt.want)
			for name, want := range tt.want {
				if got[name] != want {
					t.Errorf("channel %s notified %d times, want %d", name, got[name], want)
				}
			}
		})
	}
}

// escalationNoteContents returns the contents of the escalation engine's
// notes on an alert, oldest first.
func escalationNoteContents(t *testing.T, mgr *Manager, id uuid.UUID) []string {
	t.Helper()
	alert, err := mgr.GetAlert(context.Background(), id)
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}
	var notes []string
	for _, n := range alert.Notes {
		if n.Author == escalationNoteAuthor {
			notes = append(notes, n.Content)
		}
	}
	return notes
}

// TestEscalationNotRepeatedAfterRestart is a regression test for escalation
// steps firing a second time after a restart. Escalation tracking lives only
// in the engine's memory, so once LoadFromDB restored an unacknowledged alert
// every step that was already due was paged (and noted) again. The engine
// must recognise the steps recorded by the escalation notes persisted with
// the alert, and still escalate the steps that became due since.
func TestEscalationNotRepeatedAfterRestart(t *testing.T) {
	ctx := context.Background()
	policy := EscalationPolicy{ID: "p1", Name: "oncall", Enabled: true, Rules: []EscalationRule{
		{After: 10 * time.Minute, Channels: []string{"oncall"}, Message: "first page"},
		{After: 15 * time.Minute, Channels: []string{"oncall"}, Message: "second page"},
		{After: time.Hour, Channels: []string{"oncall"}, Message: "not yet due"},
	}}
	newEngine := func(mgr *Manager) (*EscalationEngine, *mockChannel) {
		engine := NewEscalationEngine(mgr)
		ch := newMockChannel("oncall")
		engine.RegisterChannel(ch)
		engine.AddPolicy(policy)
		return engine, ch
	}

	// First lifetime: the alert is 12 minutes old, so only step 0 is due.
	before := NewManager(DefaultManagerConfig(), nil)
	corrAlert := makeCorrelationAlert("restart-rule", "restart-group", "Restart", 9)
	corrAlert.Timestamp = time.Now().Add(-12 * time.Minute)
	if err := before.HandleCorrelationAlert(ctx, corrAlert); err != nil {
		t.Fatalf("HandleCorrelationAlert: %v", err)
	}
	engine, ch := newEngine(before)
	engine.checkEscalations(ctx)
	if got := waitForSends(t, map[string]*mockChannel{"oncall": ch}, map[string]int{"oncall": 1}); got["oncall"] != 1 {
		t.Fatalf("before restart: oncall notified %d times, want 1", got["oncall"])
	}

	// Restart 8 minutes later: the alert is restored with its notes (as
	// LoadFromDB does) and step 1 has become due in the meantime.
	restored, err := before.GetAlert(ctx, corrAlert.ID)
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}
	restored.CreatedAt = time.Now().Add(-20 * time.Minute)
	after := NewManager(DefaultManagerConfig(), nil)
	after.alerts[restored.ID] = restored

	engine, ch = newEngine(after)
	for i := 0; i < 3; i++ {
		engine.checkEscalations(ctx)
	}
	if got := waitForSends(t, map[string]*mockChannel{"oncall": ch}, map[string]int{"oncall": 1}); got["oncall"] != 1 {
		t.Errorf("after restart: oncall notified %d times, want 1 (only the step that became due)", got["oncall"])
	}
	notes := escalationNoteContents(t, after, corrAlert.ID)
	if len(notes) != 2 || !strings.Contains(notes[0], "first page") || !strings.Contains(notes[1], "second page") {
		t.Errorf("escalation notes after restart = %q, want one note per fired step", notes)
	}
}

// TestEscalationCheckDoesNotQueryDatabase is a regression test for the
// escalation loop scanning the alerts table on every tick. It listed new
// alerts through ListAlerts, which falls back to ClickHouse (a full
// newest-version scan of the table) whenever no in-memory alert matches,
// and that is the normal state once every alert has been triaged. The scan
// could also return a stale "new" version of an alert that is acknowledged
// in memory (because writing the acknowledgement failed) and page for it.
// Escalation works on the in-memory alerts, which LoadFromDB restores at
// startup.
func TestEscalationCheckDoesNotQueryDatabase(t *testing.T) {
	rec := &recordingDB{}
	db := sql.OpenDB(rec)
	defer db.Close()

	ctx := context.Background()
	mgr := NewManager(DefaultManagerConfig(), db)
	engine := NewEscalationEngine(mgr)
	for _, p := range BuiltinEscalationPolicies() {
		engine.AddPolicy(p)
	}
	corrAlert := makeCorrelationAlert("idle-rule", "idle-group", "Triaged", 9)
	corrAlert.Timestamp = time.Now().Add(-2 * time.Hour)
	if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
		t.Fatalf("HandleCorrelationAlert: %v", err)
	}
	if err := mgr.AcknowledgeAlert(ctx, corrAlert.ID, "alice"); err != nil {
		t.Fatalf("AcknowledgeAlert: %v", err)
	}

	for i := 0; i < 3; i++ {
		engine.checkEscalations(ctx)
	}

	rec.mu.Lock()
	queries := slices.Clone(rec.queries)
	rec.mu.Unlock()
	if len(queries) != 0 {
		t.Errorf("escalation checks queried the database %d times: %q", len(queries), queries)
	}
}
