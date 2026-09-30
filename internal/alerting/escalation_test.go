package alerting

import (
	"context"
	"testing"
	"time"
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
