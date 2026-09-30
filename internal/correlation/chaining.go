package correlation

import (
	"log/slog"
	"time"

	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// Metadata keys of the synthetic alert.fired events built by AlertReinjector.
const (
	metaIsSynthetic = "is_synthetic"
	metaChainDepth  = "chain_depth"
)

// MaxChainDepth bounds rule chaining: an alert is re-injected only while the
// chain that produced it is shallower than this. An alert raised from
// ordinary events has depth 0, an alert raised from re-injected alerts has
// the depth of those alerts, and each re-injection adds one, so kill chains
// can still be built on top of other chains without alerts looping forever.
const MaxChainDepth = 3

// chainDepth returns the chain depth recorded in event or alert metadata.
func chainDepth(meta map[string]any) int {
	switch d := meta[metaChainDepth].(type) {
	case int:
		return d
	case int64:
		return int(d)
	case float64:
		return int(d)
	}
	return 0
}

// AlertReinjector converts fired alerts into synthetic events and feeds them
// back into the correlation engine for rule chaining (depends_on).
//
// The engine only evaluates the synthetic events against rules that consume
// alerts (rules with depends_on, or that match on the alert.fired action or
// on alert metadata such as metadata.rule_id).
type AlertReinjector struct {
	engine *Engine
}

// NewAlertReinjector creates a reinjector wired to the given engine.
func NewAlertReinjector(engine *Engine) *AlertReinjector {
	return &AlertReinjector{engine: engine}
}

// Reinject converts an alert to a synthetic event and feeds it back. Alerts
// at MaxChainDepth are not re-injected.
func (r *AlertReinjector) Reinject(alert *Alert) {
	depth := chainDepth(alert.Metadata)
	if depth >= MaxChainDepth {
		slog.Debug("not re-injecting alert: maximum chain depth reached",
			"alert_id", alert.ID,
			"rule_id", alert.RuleID,
			"chain_depth", depth,
		)
		return
	}

	event := &schema.Event{
		EventID:   uuid.New(),
		Timestamp: alert.Timestamp,
		Source: schema.Source{
			Product: "boundary-siem-correlation",
		},
		Action:   "alert.fired",
		Outcome:  schema.OutcomeSuccess,
		Severity: alert.Severity,
		Target:   alert.RuleName,
		Metadata: map[string]any{
			"alert_id":      alert.ID.String(),
			"rule_id":       alert.RuleID,
			"rule_name":     alert.RuleName,
			"group_key":     alert.GroupKey,
			"event_count":   len(alert.Events),
			metaIsSynthetic: true,
			metaChainDepth:  depth + 1,
		},
		SchemaVersion: schema.SchemaVersionCurrent,
		ReceivedAt:    time.Now(),
		TenantID:      "system",
	}

	if alert.MITRE != nil {
		event.Metadata["mitre_tactic"] = alert.MITRE.TacticID
		event.Metadata["mitre_technique"] = alert.MITRE.TechniqueID
	}

	for _, tag := range alert.Tags {
		event.Metadata["tag_"+tag] = true
	}

	r.engine.ProcessEvent(event)

	slog.Debug("reinjected alert as synthetic event",
		"alert_id", alert.ID,
		"rule_id", alert.RuleID,
		"synthetic_event_id", event.EventID,
	)
}

// ChainDef defines a kill-chain pattern built from rule dependencies.
type ChainDef struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Stages      []string `yaml:"stages" json:"stages"` // ordered rule IDs
	Window      string   `yaml:"window" json:"window"` // max span
	Severity    int      `yaml:"severity" json:"severity"`
}

// BuiltinChains returns pre-built kill chain definitions for blockchain attacks.
//
// Every stage is the ID of a detection rule shipped in
// internal/detection/rules (GetAllRules), which siem-ingest registers
// alongside these chains; a test there checks that every stage resolves.
func BuiltinChains() []ChainDef {
	return []ChainDef{
		{
			ID:          "chain-recon-exploit-drain",
			Name:        "Blockchain Attack Chain: Recon → Exploit → Drain",
			Description: "Multi-stage attack: RPC enumeration, then exploit, then fund drain",
			// RPC Enumeration Attack → Blocked RPC Method Access → Large ETH Transfer
			Stages:   []string{"sec-002", "sec-001", "tx-001"},
			Window:   "1h",
			Severity: 10,
		},
		{
			ID:          "chain-credential-theft",
			Name:        "Credential Theft Chain: Brute Force → Stuffing → Exfil",
			Description: "Credential attack escalation: brute force, then credential stuffing, then large transfer",
			// Authentication Failure Spike → Multi-System Authentication Failure → Large ETH Transfer
			Stages:   []string{"sec-004", "eco-001", "tx-001"},
			Window:   "2h",
			Severity: 10,
		},
		{
			ID:          "chain-validator-compromise",
			Name:        "Validator Compromise Chain",
			Description: "Validator compromise: missed attestations, then slashing risk, then suspicious withdrawal",
			// Multiple Missed Attestations → Double Voting Detected → Withdrawal Key Access
			Stages:   []string{"val-004", "val-002", "key-007"},
			Window:   "4h",
			Severity: 10,
		},
	}
}

// ChainToRule converts a ChainDef to a sequence-based correlation Rule
// that matches on synthetic alert.fired events from the dependency rules.
func ChainToRule(chain ChainDef) *Rule {
	steps := make([]SequenceStep, len(chain.Stages))
	for i, ruleID := range chain.Stages {
		steps[i] = SequenceStep{
			Name: ruleID,
			Conditions: []Condition{
				{Field: "action", Operator: "eq", Value: "alert.fired"},
				{Field: "metadata.rule_id", Operator: "eq", Value: ruleID},
			},
			Required: true,
		}
	}

	var dependsOn []string
	seen := make(map[string]bool, len(chain.Stages))
	for _, ruleID := range chain.Stages {
		if !seen[ruleID] {
			seen[ruleID] = true
			dependsOn = append(dependsOn, ruleID)
		}
	}

	windowDur := 1 * time.Hour
	if chain.Window != "" {
		if d, err := time.ParseDuration(chain.Window); err == nil {
			windowDur = d
		}
	}

	return &Rule{
		ID:          chain.ID,
		Name:        chain.Name,
		Description: chain.Description,
		Type:        RuleTypeSequence,
		Enabled:     true,
		Severity:    chain.Severity,
		Category:    "Kill Chain",
		Tags:        []string{"kill-chain", "multi-stage"},
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "eq", Value: "alert.fired"},
			},
		},
		Window: windowDur,
		Sequence: &SequenceConfig{
			Ordered: true,
			MaxSpan: windowDur,
			Steps:   steps,
		},
		DependsOn: dependsOn,
	}
}
