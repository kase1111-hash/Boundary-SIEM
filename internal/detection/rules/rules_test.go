package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// shippedRulesDir is the repository's rules/ directory of YAML rules.
const shippedRulesDir = "../../../rules"

// Exact counts of shipped rules. They are asserted so that a rule silently
// disappearing (or failing validation) is caught. The README advertises
// "143 built-in rules"; the real number is what these constants say.
const (
	wantDetectionRules = 130 // GetAllRules()
	wantKillChains     = 3   // correlation.BuiltinChains()
	wantYAMLRules      = 5   // rules/*.yaml
)

func loadShippedYAMLRules(t *testing.T) map[string][]*correlation.Rule {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(shippedRulesDir, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no YAML rules found in %s", shippedRulesDir)
	}
	out := make(map[string][]*correlation.Rule, len(files))
	for _, f := range files {
		data, err := os.ReadFile(filepath.Clean(f))
		if err != nil {
			t.Fatal(err)
		}
		rules, err := correlation.ParseRules(data)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
			continue
		}
		out[filepath.Base(f)] = rules
	}
	return out
}

// shippedRuleSet returns every rule siem-ingest registers: the detection
// rules, the kill-chain rules and the YAML rules shipped in rules/.
func shippedRuleSet(t *testing.T) []*correlation.Rule {
	t.Helper()
	all := GetAllRules()
	for _, chain := range correlation.BuiltinChains() {
		all = append(all, correlation.ChainToRule(chain))
	}
	files := loadShippedYAMLRules(t)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		all = append(all, files[name]...)
	}
	return all
}

// Regression (R20/H13): exch-005 and sc-010 failed validation and were
// silently dropped at startup. Every shipped rule must validate.
func TestShippedRulesValidateAndAreCounted(t *testing.T) {
	detection := GetAllRules()
	for _, r := range detection {
		if err := r.Validate(); err != nil {
			t.Errorf("detection rule %s: %v", r.ID, err)
		}
	}
	chains := correlation.BuiltinChains()
	for _, c := range chains {
		if err := correlation.ChainToRule(c).Validate(); err != nil {
			t.Errorf("kill chain %s: %v", c.ID, err)
		}
	}
	yamlCount := 0
	for name, rules := range loadShippedYAMLRules(t) {
		for _, r := range rules {
			yamlCount++
			if err := r.Validate(); err != nil {
				t.Errorf("%s rule %s: %v", name, r.ID, err)
			}
		}
	}

	if len(detection) != wantDetectionRules {
		t.Errorf("detection rules = %d, want %d", len(detection), wantDetectionRules)
	}
	if len(chains) != wantKillChains {
		t.Errorf("kill chains = %d, want %d", len(chains), wantKillChains)
	}
	if yamlCount != wantYAMLRules {
		t.Errorf("YAML rules = %d, want %d", yamlCount, wantYAMLRules)
	}
	t.Logf("shipped rules: %d detection + %d kill chains + %d YAML = %d (README claims 143)",
		len(detection), len(chains), yamlCount, len(detection)+len(chains)+yamlCount)
}

func TestFormerlyInvalidRulesAreThresholdRules(t *testing.T) {
	byID := make(map[string]*correlation.Rule)
	for _, r := range GetAllRules() {
		byID[r.ID] = r
	}
	for _, id := range []string{"exch-005", "sc-010"} {
		r, ok := byID[id]
		if !ok {
			t.Errorf("rule %s missing", id)
			continue
		}
		if r.Type != correlation.RuleTypeThreshold {
			t.Errorf("rule %s type = %s, want threshold (its config is a threshold)", id, r.Type)
		}
		if err := r.Validate(); err != nil {
			t.Errorf("rule %s: %v", id, err)
		}
	}
}

func TestShippedRuleIDsAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, r := range shippedRuleSet(t) {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %s", r.ID)
		}
		seen[r.ID] = true
	}
}

// Regression (R15/H12): kill-chain stages and the depends_on of
// community-recon-then-exploit named rules siem-ingest never registers, so
// they could never fire.
func TestChainStagesAndDependenciesResolve(t *testing.T) {
	all := shippedRuleSet(t)
	known := make(map[string]bool, len(all))
	for _, r := range all {
		known[r.ID] = true
	}

	if err := correlation.ValidateDependencies(all, nil); err != nil {
		t.Errorf("ValidateDependencies: %v", err)
	}
	for _, chain := range correlation.BuiltinChains() {
		for _, stage := range chain.Stages {
			if !known[stage] {
				t.Errorf("chain %s: stage %q is not a registered rule", chain.ID, stage)
			}
		}
	}
	for _, r := range all {
		for _, dep := range r.DependsOn {
			if !known[dep] {
				t.Errorf("rule %s: depends_on %q is not a registered rule", r.ID, dep)
			}
		}
		if r.Sequence == nil {
			continue
		}
		for _, step := range r.Sequence.Steps {
			for _, c := range step.Conditions {
				if c.Field == "metadata.rule_id" {
					if id, _ := c.Value.(string); !known[id] {
						t.Errorf("rule %s step %s: waits for alerts of unregistered rule %q", r.ID, step.Name, id)
					}
				}
			}
		}
	}
}

// wireLikeSiemIngest builds an engine the way cmd/siem-ingest does: detection
// rules, alert re-injection for chaining, kill chains and the YAML rules.
func wireLikeSiemIngest(t *testing.T, onAlert func(*correlation.Alert)) *correlation.Engine {
	t.Helper()
	cfg := correlation.DefaultEngineConfig()
	cfg.StateCleanupFreq = time.Hour
	e := correlation.NewEngine(cfg)
	for _, r := range shippedRuleSet(t) {
		if err := e.AddRule(r); err != nil {
			// siem-ingest logs and skips rules that fail to load.
			t.Errorf("AddRule(%s): %v", r.ID, err)
		}
	}
	e.AddHandler(func(_ context.Context, a *correlation.Alert) error {
		onAlert(a)
		return nil
	})
	reinjector := correlation.NewAlertReinjector(e)
	e.AddHandler(func(_ context.Context, a *correlation.Alert) error {
		reinjector.Reinject(a)
		return nil
	})
	return e
}

func event(action string, outcome schema.Outcome, meta map[string]any) *schema.Event {
	return &schema.Event{
		EventID:   uuid.New(),
		Timestamp: time.Now(),
		Source:    schema.Source{Product: "probe", Host: "host-1"},
		Action:    action,
		Outcome:   outcome,
		Severity:  1,
		Actor:     &schema.Actor{ID: "actor-1", IPAddress: "203.0.113.7"},
		Target:    "target-1",
		Metadata:  meta,
		TenantID:  "default",
	}
}

// Regression (R05/H02): one benign event produced ~1,259 alerts because rule
// filters were ignored and every alert was re-injected into every rule.
func TestBenignEventTriggersNoShippedRule(t *testing.T) {
	var fired atomic.Int64
	var mu sync.Mutex
	var ruleIDs []string
	e := wireLikeSiemIngest(t, func(a *correlation.Alert) {
		fired.Add(1)
		mu.Lock()
		ruleIDs = append(ruleIDs, a.RuleID)
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Start(ctx)
	defer e.Stop()

	e.ProcessEvent(event("rt.unrelated.benign", schema.OutcomeSuccess, nil))
	e.ProcessEvent(event("user.login", schema.OutcomeSuccess, nil))
	time.Sleep(500 * time.Millisecond)

	if n := fired.Load(); n != 0 {
		mu.Lock()
		defer mu.Unlock()
		if len(ruleIDs) > 10 {
			ruleIDs = ruleIDs[:10]
		}
		t.Errorf("benign events fired %d alert(s), first rules: %v", n, ruleIDs)
	}
}

// Review: a numeric condition such as "metadata.value_eth gte 1000" compared
// a missing field as the string "<nil>", which sorts above every number, so
// every evm.transaction or tx.transfer without the field fired tx-001 ("Large
// ETH Transfer", the last stage of two kill chains) and other critical rules.
func TestNumericConditionsNeedTheField(t *testing.T) {
	var mu sync.Mutex
	counts := make(map[string]int)
	e := wireLikeSiemIngest(t, func(a *correlation.Alert) {
		mu.Lock()
		counts[a.RuleID]++
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Start(ctx)
	defer e.Stop()

	for _, action := range []string{"evm.transaction", "tx.transfer", "tx.submitted", "defi.swap", "block.reorg"} {
		e.ProcessEvent(event(action, schema.OutcomeSuccess, nil))
		e.ProcessEvent(event(action, schema.OutcomeSuccess, map[string]any{"value_eth": "n/a", "value_usd": "n/a"}))
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	if len(counts) != 0 {
		t.Errorf("events without the compared numeric field fired %v", counts)
	}
	mu.Unlock()

	// The field present and large enough still fires.
	e.ProcessEvent(event("evm.transaction", schema.OutcomeSuccess, map[string]any{"value_eth": 5000.0, "from": "0xabc"}))
	waitFor(t, &mu, counts, "tx-001")
}

// Rules still fire on the events they describe, and chaining still works: a
// kill chain completes from the alerts of its stage rules.
func TestShippedRulesFireOnIntendedEvents(t *testing.T) {
	var mu sync.Mutex
	counts := make(map[string]int)
	e := wireLikeSiemIngest(t, func(a *correlation.Alert) {
		mu.Lock()
		counts[a.RuleID]++
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Start(ctx)
	defer e.Stop()

	send := func(ev *schema.Event, n int) {
		for i := 0; i < n; i++ {
			e.ProcessEvent(ev)
			ev = event(ev.Action, ev.Outcome, ev.Metadata)
		}
	}
	// sec-005: a single key export attempt.
	send(event("key.export", schema.OutcomeSuccess, nil), 1)
	// chain-validator-compromise: missed attestations, a double vote, then
	// access to the withdrawal key.
	send(event("validator.attestation_missed", schema.OutcomeFailure, map[string]any{"validator_index": 42}), 3)
	waitFor(t, &mu, counts, "val-004")
	send(event("validator.double_vote", schema.OutcomeFailure, map[string]any{"validator_index": 42}), 1)
	waitFor(t, &mu, counts, "val-002")
	send(event("key.access", schema.OutcomeSuccess, map[string]any{"key_type": "withdrawal"}), 1)
	waitFor(t, &mu, counts, "key-007")
	waitFor(t, &mu, counts, "chain-validator-compromise")

	// community-recon-then-exploit: RPC method enumeration from one source,
	// then a call to an admin RPC method from the same source.
	for i := 0; i < 20; i++ {
		ev := event("rpc.eth_call", schema.OutcomeSuccess, nil)
		ev.Target = fmt.Sprintf("method-%d", i)
		e.ProcessEvent(ev)
	}
	waitFor(t, &mu, counts, "sec-002")
	send(event("rpc.admin", schema.OutcomeFailure, nil), 1)
	waitFor(t, &mu, counts, "sec-001")
	waitFor(t, &mu, counts, "community-recon-then-exploit")

	mu.Lock()
	defer mu.Unlock()
	for _, id := range []string{"sec-005", "chain-validator-compromise", "community-recon-then-exploit"} {
		if counts[id] != 1 {
			t.Errorf("%s fired %d time(s), want 1", id, counts[id])
		}
	}
}

func waitFor(t *testing.T, mu *sync.Mutex, counts map[string]int, ruleID string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := counts[ruleID]
		mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("rule %s did not fire", ruleID)
}
