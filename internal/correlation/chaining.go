package correlation

import (
	"log/slog"
	"time"

	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// Metadata keys of the synthetic alert.fired events built by AlertReinjector.
//
// is_synthetic and chain_depth are for rule authors to test. The engine never
// trusts them on an event: ingested events carry arbitrary metadata, so an
// event could claim to be synthetic (and skip every rule that does not
// consume alerts) or claim the maximum chain depth (and keep the alerts it
// causes from being chained). The engine relies on metaReinjected instead.
const (
	metaIsSynthetic = "is_synthetic"
	metaChainDepth  = "chain_depth"
	metaReinjected  = "_reinjected"
)

// reinjected is the metaReinjected value of an event built by
// AlertReinjector. Its type is unexported, so no ingested event (decoded from
// JSON, CEF, syslog, ...) can carry one.
type reinjected struct{ depth int }

// reinjectedDepth reports whether event was built by AlertReinjector and, if
// so, the chain depth it carries.
func reinjectedDepth(event *schema.Event) (int, bool) {
	r, ok := event.Metadata[metaReinjected].(reinjected)
	return r.depth, ok
}

// MaxChainDepth bounds rule chaining: an alert is re-injected only while the
// chain that produced it is shallower than this. An alert raised from
// ordinary events has depth 0, an alert raised from re-injected alerts has
// the depth of those alerts, and each re-injection adds one, so kill chains
// can still be built on top of other chains without alerts looping forever.
const MaxChainDepth = 3

// chainDepth returns the chain depth recorded in alert metadata (never
// negative).
func chainDepth(meta map[string]any) int {
	var depth int
	switch d := meta[metaChainDepth].(type) {
	case int:
		depth = d
	case int64:
		depth = int(d)
	case float64:
		depth = int(d)
	}
	return max(depth, 0)
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
// at MaxChainDepth and recurrences (see Alert.Recurrence) are not
// re-injected: a recurrence is the detection already chained continuing,
// and chain rules keep seeing one alert.fired event per dedup window.
func (r *AlertReinjector) Reinject(alert *Alert) {
	if alert.Recurrence {
		return
	}
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
		Action:        "alert.fired",
		Outcome:       schema.OutcomeSuccess,
		Severity:      alert.Severity,
		Target:        alert.RuleName,
		Metadata:      make(map[string]any),
		SchemaVersion: schema.SchemaVersionCurrent,
		ReceivedAt:    time.Now(),
		TenantID:      "system",
	}

	// The entity of the event that raised the alert (who did it, and its
	// metadata such as metadata.from or metadata.validator_index), so that a
	// chain can require all of its stages to concern the same entity.
	// Alert fields are set below and always win.
	if t := alert.trigger; t != nil {
		if t.Actor != nil {
			actor := *t.Actor
			event.Actor = &actor
		}
		for k, v := range t.Metadata {
			if !isAlertField(k) && k != metaReinjected {
				event.Metadata[k] = v
			}
		}
	}
	for k, v := range map[string]any{
		"alert_id":      alert.ID.String(),
		"rule_id":       alert.RuleID,
		"rule_name":     alert.RuleName,
		"group_key":     alert.GroupKey,
		"event_count":   len(alert.Events),
		metaIsSynthetic: true,
		metaChainDepth:  depth + 1,
		metaReinjected:  reinjected{depth: depth + 1},
	} {
		event.Metadata[k] = v
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
//
// GroupBy names the entity every stage must concern, as fields of the event
// that raised each stage alert (AlertReinjector copies its actor and
// metadata into the re-injected alert.fired event): "actor.ip" requires all
// stages to have been raised by events from the same source IP. Stage alerts
// whose event lacks the field are not counted. Without GroupBy the stages
// may concern unrelated entities, which is what made the built-in chains
// fire for three unrelated actors (E2E round 1).
type ChainDef struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Stages      []string `yaml:"stages" json:"stages"` // ordered rule IDs
	Window      string   `yaml:"window" json:"window"` // max span
	Severity    int      `yaml:"severity" json:"severity"`
	GroupBy     []string `yaml:"group_by,omitempty" json:"group_by,omitempty"`
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
			Description: "Multi-stage attack from one source IP: RPC enumeration, then exploit, then a large transfer it initiated",
			// RPC Enumeration Attack → Blocked RPC Method Access → Large ETH Transfer
			Stages:   []string{"sec-002", "sec-001", "tx-001"},
			Window:   "1h",
			Severity: 10,
			// The transfer must carry the initiator's IP (e.g. tx.transfer
			// from a wallet or custody API); on-chain evm.transaction events
			// cannot be attributed to an IP and never complete the chain.
			GroupBy: []string{"actor.ip"},
		},
		{
			ID:          "chain-credential-theft",
			Name:        "Credential Theft Chain: Brute Force → Stuffing → Exfil",
			Description: "Credential attack escalation from one source IP: brute force, then credential stuffing, then a large transfer it initiated",
			// Authentication Failure Spike → Multi-System Authentication Failure → Large ETH Transfer
			Stages:   []string{"sec-004", "eco-001", "tx-001"},
			Window:   "2h",
			Severity: 10,
			GroupBy:  []string{"actor.ip"},
		},
		{
			ID:          "chain-validator-compromise",
			Name:        "Validator Compromise Chain",
			Description: "Validator compromise: missed attestations, then slashing risk, then access to the same validator's withdrawal key",
			// Multiple Missed Attestations → Double Voting Detected → Withdrawal Key Access
			Stages:   []string{"val-004", "val-002", "key-007"},
			Window:   "4h",
			Severity: 10,
			GroupBy:  []string{"metadata.validator_index"},
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

	// Stage alerts that name no entity cannot be correlated: without these
	// conditions they would all share one "<nil>" group.
	match := []MatchCondition{{Field: "action", Operator: "eq", Value: "alert.fired"}}
	for _, field := range chain.GroupBy {
		match = append(match, MatchCondition{Field: field, Operator: "exists"})
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
		Conditions:  Conditions{Match: match},
		GroupBy:     append([]string(nil), chain.GroupBy...),
		Window:      windowDur,
		Sequence: &SequenceConfig{
			Ordered: true,
			MaxSpan: windowDur,
			Steps:   steps,
		},
		DependsOn: dependsOn,
	}
}
