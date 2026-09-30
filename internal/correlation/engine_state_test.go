package correlation

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Regression (R05): re-injection had no loop guard. An alert raised from
// alerts at MaxChainDepth is not fed back again.
func TestAlertReinjector_ChainDepthGuard(t *testing.T) {
	tests := []struct {
		name         string
		metadata     map[string]any
		wantInjected bool
		wantDepth    int
	}{
		{name: "alert from ordinary events", metadata: nil, wantInjected: true, wantDepth: 1},
		{name: "alert from a chain", metadata: map[string]any{metaChainDepth: 1}, wantInjected: true, wantDepth: 2},
		{name: "at max depth", metadata: map[string]any{metaChainDepth: MaxChainDepth}, wantInjected: false},
		{name: "depth decoded from JSON", metadata: map[string]any{metaChainDepth: float64(MaxChainDepth)}, wantInjected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEngine(DefaultEngineConfig())
			NewAlertReinjector(e).Reinject(&Alert{
				ID: uuid.New(), RuleID: "r", RuleName: "R", Severity: 5,
				Timestamp: time.Now(), Metadata: tt.metadata,
			})
			if got := len(e.eventCh) == 1; got != tt.wantInjected {
				t.Fatalf("re-injected = %v, want %v", got, tt.wantInjected)
			}
			if !tt.wantInjected {
				return
			}
			ev := <-e.eventCh
			if d := chainDepth(ev.Metadata); d != tt.wantDepth {
				t.Errorf("chain_depth = %d, want %d", d, tt.wantDepth)
			}
			if !isSynthetic(ev) {
				t.Error("re-injected event not marked synthetic")
			}
		})
	}
}

// A chain rule's alert records the chain depth of the alerts it was built
// from, and does not share (or mutate) the rule's metadata map.
func TestEngine_ChainAlertCarriesDepth(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	chain := ChainToRule(ChainDef{ID: "c", Name: "C", Stages: []string{"a", "b"}, Window: "1h", Severity: 9})
	chain.Metadata = map[string]any{"owner": "soc"}
	mustAddRule(t, e, chain)

	re := NewAlertReinjector(e)
	for _, ruleID := range []string{"a", "b"} {
		re.Reinject(&Alert{ID: uuid.New(), RuleID: ruleID, RuleName: ruleID, Severity: 5, Timestamp: time.Now()})
		e.processEvent(context.Background(), <-e.eventCh)
	}

	alerts := drainAlerts(e)
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(alerts))
	}
	if d := chainDepth(alerts[0].Metadata); d != 1 {
		t.Errorf("chain alert depth = %d, want 1", d)
	}
	alerts[0].Metadata["mutated"] = true
	if _, leaked := chain.Metadata["mutated"]; leaked {
		t.Error("alert metadata aliases the rule's metadata map")
	}
}

func TestEngine_SetRuleEnabled(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	rule := validThresholdRule()
	mustAddRule(t, e, &rule)

	updated, ok := e.SetRuleEnabled(rule.ID, false)
	if !ok || updated.Enabled {
		t.Fatalf("SetRuleEnabled = %+v, %v", updated, ok)
	}
	if !rule.Enabled {
		t.Error("SetRuleEnabled modified the shared rule in place")
	}
	if got, _ := e.GetRule(rule.ID); got.Enabled {
		t.Error("engine still reports the rule enabled")
	}
	e.processEvent(context.Background(), testEvent("auth.failure"))
	e.processEvent(context.Background(), testEvent("auth.failure"))
	e.processEvent(context.Background(), testEvent("auth.failure"))
	if n := len(drainAlerts(e)); n != 0 {
		t.Errorf("disabled rule fired %d alert(s)", n)
	}
	if _, ok := e.SetRuleEnabled("missing", true); ok {
		t.Error("SetRuleEnabled on an unknown rule reported success")
	}
}

func TestEngine_CheckDependencies(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	stage := validThresholdRule()
	stage.ID = "stage-a"
	mustAddRule(t, e, &stage)
	mustAddRule(t, e, ChainToRule(ChainDef{ID: "chain", Name: "Chain", Stages: []string{"stage-a", "stage-missing"}, Severity: 9}))

	err := e.CheckDependencies()
	if err == nil {
		t.Fatal("CheckDependencies = nil, want error for stage-missing")
	}
	if !strings.Contains(err.Error(), `"stage-missing"`) || strings.Contains(err.Error(), `"stage-a"`) {
		t.Errorf("CheckDependencies = %v, want only stage-missing reported", err)
	}
}

func TestRule_ReferencedRuleIDs(t *testing.T) {
	r := ChainToRule(ChainDef{ID: "c", Name: "C", Stages: []string{"x", "y", "x"}, Severity: 5})
	r.EventConditions = []Condition{{Field: "metadata.rule_id", Operator: "in", Values: []string{"z"}}}
	got := strings.Join(r.ReferencedRuleIDs(), ",")
	if got != "x,y,z" {
		t.Errorf("ReferencedRuleIDs = %s, want x,y,z", got)
	}
	if err := r.Validate(); err != nil {
		t.Errorf("chain with a repeated stage fails validation: %v", err)
	}
}

// Regression (H15): baseline samples are bounded by age and count even when
// Stats is never called, and cleanup drops idle metrics.
func TestBaseline_RetentionIsBounded(t *testing.T) {
	b := NewBaselineEngine()
	for i := 0; i < baselineMaxSamples+10; i++ {
		b.Record("r", "g", "m", float64(i))
	}
	store := b.metrics["r:g:m"]
	store.mu.Lock()
	n := len(store.samples)
	last := store.samples[n-1].value
	store.mu.Unlock()
	if n > baselineMaxSamples {
		t.Errorf("samples = %d, want at most %d", n, baselineMaxSamples)
	}
	if last != float64(baselineMaxSamples+9) {
		t.Errorf("newest sample = %v, want the last recorded one", last)
	}

	// Samples older than the retention age are dropped on the next Record.
	old := time.Now().Add(-baselineMaxAge - time.Hour)
	b.metrics["r:old:m"] = &metricStore{maxAge: baselineMaxAge, samples: []timedSample{{value: 1, ts: old}, {value: 2, ts: old}}}
	b.Record("r", "old", "m", 3)
	if got := len(b.metrics["r:old:m"].samples); got != 1 {
		t.Errorf("samples after recording past retention = %d, want 1", got)
	}

	// Cleanup removes metrics with nothing left inside the retention age.
	b.metrics["r:idle:m"] = &metricStore{maxAge: baselineMaxAge, samples: []timedSample{{value: 1, ts: old}}}
	b.Cleanup()
	if _, ok := b.metrics["r:idle:m"]; ok {
		t.Error("Cleanup kept an idle metric")
	}
	if _, ok := b.metrics["r:g:m"]; !ok {
		t.Error("Cleanup removed an active metric")
	}
}

// cleanupExpiredState drops idle threshold windows and fire times, keeps the
// windows absence rules use to remember which groups report, and cleans the
// baseline store.
func TestEngine_CleanupExpiredState(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.DedupWindow = time.Hour
	e := NewEngine(cfg)
	threshold := validThresholdRule()
	threshold.Window = 50 * time.Millisecond
	threshold.Threshold.Count = 1
	mustAddRule(t, e, &threshold)
	mustAddRule(t, e, heartbeatAbsenceRule([]string{"source.host"}, 50*time.Millisecond))

	e.processEvent(context.Background(), testEvent("auth.failure"))
	e.processEvent(context.Background(), testEvent("system.heartbeat"))
	drainAlerts(e)
	old := time.Now().Add(-baselineMaxAge - time.Hour)
	e.baseline.metrics["x:y:z"] = &metricStore{maxAge: baselineMaxAge, samples: []timedSample{{value: 1, ts: old}}}
	time.Sleep(80 * time.Millisecond)

	e.cleanupExpiredState()

	windows := func(id string) int {
		st := e.states[id]
		st.mu.Lock()
		defer st.mu.Unlock()
		return len(st.windows)
	}
	if n := windows(threshold.ID); n != 0 {
		t.Errorf("threshold windows after cleanup = %d, want 0", n)
	}
	if n := windows("heartbeat-absent"); n != 1 {
		t.Errorf("absence windows after cleanup = %d, want 1 (db still expected to report)", n)
	}
	st := e.states[threshold.ID]
	st.mu.Lock()
	fires := len(st.lastFire)
	st.mu.Unlock()
	if fires != 1 {
		t.Errorf("fire times after cleanup = %d, want 1 (still inside DedupWindow)", fires)
	}
	if _, ok := e.baseline.metrics["x:y:z"]; ok {
		t.Error("cleanup did not clean the baseline store")
	}
}

// Workers, the absence checker, cleanup and rule toggles run concurrently.
func TestEngine_ConcurrentEvaluation(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.StateCleanupFreq = 5 * time.Millisecond
	e := NewEngine(cfg)
	rule := validThresholdRule()
	mustAddRule(t, e, &rule)
	mustAddRule(t, e, heartbeatAbsenceRule(nil, 10*time.Millisecond))
	var mu sync.Mutex
	alerts := 0
	e.AddHandler(func(context.Context, *Alert) error {
		mu.Lock()
		alerts++
		mu.Unlock()
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	e.Start(ctx)
	for i := 0; i < 200; i++ {
		e.ProcessEvent(testEvent("auth.failure"))
		if i%20 == 0 {
			e.SetRuleEnabled(rule.ID, i%40 == 0)
		}
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	e.Stop()
	mu.Lock()
	defer mu.Unlock()
	if alerts == 0 {
		t.Error("no alerts under concurrent load")
	}
}
