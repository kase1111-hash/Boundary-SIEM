package correlation

import (
	"log/slog"
	"time"

	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// AlertReinjector converts fired alerts into synthetic events and feeds them
// back into the correlation engine for rule chaining (depends_on).
type AlertReinjector struct {
	engine *Engine
}

// NewAlertReinjector creates a reinjector wired to the given engine.
func NewAlertReinjector(engine *Engine) *AlertReinjector {
	return &AlertReinjector{engine: engine}
}

// Reinject converts an alert to a synthetic event and feeds it back.
func (r *AlertReinjector) Reinject(alert *Alert) {
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
			"alert_id":     alert.ID.String(),
			"rule_id":      alert.RuleID,
			"rule_name":    alert.RuleName,
			"group_key":    alert.GroupKey,
			"event_count":  len(alert.Events),
			"is_synthetic": true,
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
func BuiltinChains() []ChainDef {
	return []ChainDef{
		{
			ID:          "chain-recon-exploit-drain",
			Name:        "Blockchain Attack Chain: Recon → Exploit → Drain",
			Description: "Multi-stage attack: RPC enumeration, then exploit, then fund drain",
			Stages:      []string{"builtin-rpc-abuse", "builtin-unauthorized-access", "builtin-suspicious-withdrawal"},
			Window:      "1h",
			Severity:    10,
		},
		{
			ID:          "chain-credential-theft",
			Name:        "Credential Theft Chain: Brute Force → Stuffing → Exfil",
			Description: "Credential attack escalation: brute force, then credential stuffing, then large transfer",
			Stages:      []string{"builtin-brute-force", "builtin-credential-stuffing", "builtin-large-transfer"},
			Window:      "2h",
			Severity:    10,
		},
		{
			ID:          "chain-validator-compromise",
			Name:        "Validator Compromise Chain",
			Description: "Validator compromise: missed attestations, then slashing risk, then suspicious withdrawal",
			Stages:      []string{"builtin-validator-missed-attestations", "builtin-slashing-risk", "builtin-suspicious-withdrawal"},
			Window:      "4h",
			Severity:    10,
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
	}
}
