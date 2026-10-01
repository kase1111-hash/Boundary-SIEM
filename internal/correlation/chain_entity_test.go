package correlation

import (
	"context"
	"testing"
	"time"

	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// E2E round 1: kill chains had no group key, so stage alerts about
// unrelated entities completed a chain. A re-injected alert now carries the
// actor and metadata of the event that raised it, and a chain with GroupBy
// only correlates stages that concern the same entity.

func TestAlertReinjectorCarriesTriggerEntity(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())
	mustAddRule(t, e, contractTestRule()) // key.export, count 1

	trigger := testEvent("key.export")
	trigger.Actor = &schema.Actor{ID: "u1", IPAddress: "198.51.100.4"}
	trigger.Metadata = map[string]any{
		"validator_index": 12,
		// An ingested event cannot make the synthetic event claim another
		// rule, tags or chain depth.
		"rule_id": "spoofed", "tag_trusted": true, "chain_depth": 0, "is_synthetic": false,
	}
	e.processEvent(context.Background(), trigger)
	alerts := drainAlerts(e)
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(alerts))
	}
	NewAlertReinjector(e).Reinject(alerts[0])
	synthetic := <-e.eventCh

	if synthetic.Actor == nil || synthetic.Actor.IPAddress != "198.51.100.4" || synthetic.Actor == trigger.Actor {
		t.Errorf("synthetic actor = %+v, want a copy of the trigger's actor", synthetic.Actor)
	}
	m := synthetic.Metadata
	if m["validator_index"] != 12 {
		t.Errorf("metadata.validator_index = %v, want the trigger's 12", m["validator_index"])
	}
	if m["rule_id"] != alerts[0].RuleID || m["is_synthetic"] != true || m["chain_depth"] != 1 {
		t.Errorf("alert fields were overridden by the trigger's metadata: %v", m)
	}
	if _, ok := m["tag_trusted"]; ok {
		t.Error("the trigger's tag_ metadata leaked into the alert's tags")
	}
	if d, ok := reinjectedDepth(synthetic); !ok || d != 1 {
		t.Errorf("reinjected marker = %d, %v", d, ok)
	}
}

func TestChainToRuleGroupsByEntity(t *testing.T) {
	r := ChainToRule(ChainDef{ID: "c", Name: "C", Stages: []string{"a", "b"}, Window: "1h", Severity: 9, GroupBy: []string{"actor.ip"}})
	if len(r.GroupBy) != 1 || r.GroupBy[0] != "actor.ip" {
		t.Errorf("GroupBy = %v, want [actor.ip]", r.GroupBy)
	}
	var requiresEntity bool
	for _, m := range r.Conditions.Match {
		if m.Field == "actor.ip" && m.Operator == "exists" {
			requiresEntity = true
		}
	}
	if !requiresEntity {
		t.Errorf("match conditions %v do not require the entity field", r.Conditions.Match)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}

	e := NewEngine(DefaultEngineConfig())
	mustAddRule(t, e, r)
	re := NewAlertReinjector(e)
	stage := func(ruleID, ip string) {
		a := &Alert{ID: uuid.New(), RuleID: ruleID, RuleName: ruleID, Severity: 5, Timestamp: time.Now()}
		if ip != "" {
			a.trigger = &schema.Event{Actor: &schema.Actor{IPAddress: ip}}
		}
		re.Reinject(a)
		e.processEvent(context.Background(), <-e.eventCh)
	}

	stage("a", "192.0.2.1")
	stage("b", "192.0.2.2") // another source
	stage("a", "")
	stage("b", "") // no entity: not correlated
	if n := len(drainAlerts(e)); n != 0 {
		t.Fatalf("chain fired %d time(s) for stages about different or unknown entities", n)
	}
	stage("b", "192.0.2.1")
	alerts := drainAlerts(e)
	if len(alerts) != 1 || alerts[0].GroupKey != "[actor.ip=192.0.2.1]" {
		t.Fatalf("alerts = %+v, want one chain alert for 192.0.2.1", alerts)
	}
}

func TestBuiltinChainsNameAnEntity(t *testing.T) {
	for _, c := range BuiltinChains() {
		if len(c.GroupBy) == 0 {
			t.Errorf("built-in chain %s has no GroupBy: its stages may concern unrelated entities", c.ID)
		}
	}
}
