package finiteintent

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/schema"
)

// ActionMappings maps FIE event types to canonical action names.
var ActionMappings = map[string]string{
	// Intent lifecycle events
	"intent.captured":    "fie.intent.captured",
	"intent.modified":    "fie.intent.modified",
	"intent.activated":   "fie.intent.activated",
	"intent.executing":   "fie.intent.executing",
	"intent.completed":   "fie.intent.completed",
	"intent.sunset":      "fie.intent.sunset",

	// Trigger events
	"trigger.deadman.activated": "fie.trigger.deadman",
	"trigger.quorum.activated":  "fie.trigger.quorum",
	"trigger.oracle.activated":  "fie.trigger.oracle",
	"trigger.validated":         "fie.trigger.validated",
	"trigger.rejected":          "fie.trigger.rejected",
	"trigger.expired":           "fie.trigger.expired",

	// Execution agent events
	"execution.decision":       "fie.execution.decision",
	"execution.ip_transfer":    "fie.execution.ip_transfer",
	"execution.asset_distribute": "fie.execution.asset_distribute",
	"execution.goal_execute":   "fie.execution.goal_execute",
	"execution.blocked":        "fie.execution.blocked",
	"execution.low_confidence": "fie.execution.low_confidence",

	// IP Token events
	"ip.token.created":      "fie.ip.created",
	"ip.token.transferred":  "fie.ip.transferred",
	"ip.token.licensed":     "fie.ip.licensed",
	"ip.token.public_domain": "fie.ip.public_domain",
	"ip.token.revoked":      "fie.ip.revoked",

	// Sunset events
	"sunset.initiated":     "fie.sunset.initiated",
	"sunset.ip_transition": "fie.sunset.ip_transition",
	"sunset.asset_release": "fie.sunset.asset_release",
	"sunset.complete":      "fie.sunset.complete",

	// Oracle events
	"oracle.requested":  "fie.oracle.requested",
	"oracle.fulfilled":  "fie.oracle.fulfilled",
	"oracle.disputed":   "fie.oracle.disputed",
	"oracle.timeout":    "fie.oracle.timeout",

	// Security events
	"security.access_change":       "fie.security.access_change",
	"security.role_assignment":     "fie.security.role_assignment",
	"security.constraint_violation": "fie.security.constraint_violation",
	"security.anomaly":             "fie.security.anomaly",
	"security.political_content":   "fie.security.political_content",
}

// Normalizer converts FIE events to canonical SIEM schema.
type Normalizer struct {
	defaultTenantID string
	sourceProduct   string
	sourceHost      string
	sourceVersion   string
}

// NormalizerConfig holds configuration for the normalizer.
type NormalizerConfig struct {
	DefaultTenantID string
	SourceHost      string
	SourceVersion   string
}

// DefaultNormalizerConfig returns the default normalizer configuration.
func DefaultNormalizerConfig() NormalizerConfig {
	return NormalizerConfig{
		DefaultTenantID: "default",
		SourceHost:      "localhost",
		SourceVersion:   "1.0.0",
	}
}

// NewNormalizer creates a new FIE normalizer.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	return &Normalizer{
		defaultTenantID: cfg.DefaultTenantID,
		sourceProduct:   "finite-intent-executor",
		sourceHost:      cfg.SourceHost,
		sourceVersion:   cfg.SourceVersion,
	}
}

// NormalizeIntent converts a FIE intent to a canonical event.
func (n *Normalizer) NormalizeIntent(intent *Intent, eventType string) (*schema.Event, error) {
	action := n.mapAction(eventType)
	severity := n.calculateIntentSeverity(intent, eventType)

	timestamp := intent.CreatedAt
	if intent.ModifiedAt != nil && eventType == "intent.modified" {
		timestamp = *intent.ModifiedAt
	}
	if intent.ActivatedAt != nil && eventType == "intent.activated" {
		timestamp = *intent.ActivatedAt
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: intent.ID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("intent:%s", intent.ID),
		Outcome:  n.determineIntentOutcome(intent, eventType),
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   intent.CreatorID,
			Name: intent.CreatorAddress,
		},

		Metadata: map[string]any{
			"fie_intent_id":      intent.ID,
			"fie_content_hash":   intent.ContentHash,
			"fie_trigger_type":   intent.TriggerType,
			"fie_status":         intent.Status,
			"fie_goal_count":     len(intent.Goals),
			"fie_asset_count":    len(intent.Assets),
		},
	}

	return event, nil
}

// NormalizeTrigger converts a trigger event to a canonical event.
func (n *Normalizer) NormalizeTrigger(trigger *TriggerEvent, eventType string) (*schema.Event, error) {
	action := n.mapAction(eventType)
	severity := n.calculateTriggerSeverity(trigger)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     trigger.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: trigger.ID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("intent:%s", trigger.IntentID),
		Outcome:  n.determineTriggerOutcome(trigger),
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   trigger.ValidatorID,
			Name: "trigger-validator",
		},

		Metadata: map[string]any{
			"fie_trigger_id":     trigger.ID,
			"fie_intent_id":      trigger.IntentID,
			"fie_trigger_type":   trigger.TriggerType,
			"fie_trigger_status": trigger.Status,
			"fie_confidence":     trigger.Confidence,
			"fie_evidence_count": len(trigger.Evidence),
		},
	}

	return event, nil
}

// NormalizeExecution converts an execution event to a canonical event.
func (n *Normalizer) NormalizeExecution(exec *ExecutionEvent) (*schema.Event, error) {
	eventType := "execution." + exec.ActionType
	action := n.mapAction(eventType)
	severity := n.calculateExecutionSeverity(exec)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     exec.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: exec.ID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("intent:%s", exec.IntentID),
		Outcome:  n.determineExecutionOutcome(exec),
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   "execution-agent",
			Name: "execution-agent",
		},

		Metadata: map[string]any{
			"fie_execution_id":    exec.ID,
			"fie_intent_id":       exec.IntentID,
			"fie_action_type":     exec.ActionType,
			"fie_confidence":      exec.ConfidenceScore,
			"fie_corpus_citation": exec.CorpusCitation,
			"fie_blocked_reason":  exec.BlockedReason,
		},
	}

	return event, nil
}

// NormalizeIPToken converts an IP token event to a canonical event.
func (n *Normalizer) NormalizeIPToken(token *IPToken, eventType string) (*schema.Event, error) {
	action := n.mapAction(eventType)

	timestamp := token.CreatedAt
	if token.TransferredAt != nil && eventType == "ip.token.transferred" {
		timestamp = *token.TransferredAt
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: token.ContractAddr,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("ip_token:%s", token.TokenID),
		Outcome:  schema.OutcomeSuccess,
		Severity: n.calculateIPTokenSeverity(token, eventType),

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   token.Owner,
			Name: token.Owner,
		},

		Metadata: map[string]any{
			"fie_token_id":       token.TokenID,
			"fie_intent_id":      token.IntentID,
			"fie_contract_addr":  token.ContractAddr,
			"fie_ip_type":        token.IPType,
			"fie_license_type":   token.LicenseType,
			"fie_royalty_rate":   token.RoyaltyRate,
			"fie_token_status":   token.Status,
		},
	}

	return event, nil
}

// NormalizeSunset converts a sunset event to a canonical event.
func (n *Normalizer) NormalizeSunset(sunset *SunsetEvent) (*schema.Event, error) {
	eventType := "sunset." + sunset.Phase
	action := n.mapAction(eventType)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     sunset.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: sunset.ID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("intent:%s", sunset.IntentID),
		Outcome:  schema.OutcomeSuccess,
		Severity: 4, // Sunset events are important but expected

		Actor: &schema.Actor{
			Type: schema.ActorSystem,
			ID:   "sunset-protocol",
			Name: "sunset-protocol",
		},

		Metadata: map[string]any{
			"fie_sunset_id":       sunset.ID,
			"fie_intent_id":       sunset.IntentID,
			"fie_sunset_phase":    sunset.Phase,
			"fie_assets_released": sunset.AssetsReleased,
			"fie_ip_transitioned": sunset.IPTransitioned,
			"fie_public_domain_tx": sunset.PublicDomainTx,
		},
	}

	return event, nil
}

// NormalizeOracle converts an oracle event to a canonical event.
func (n *Normalizer) NormalizeOracle(oracle *OracleEvent) (*schema.Event, error) {
	eventType := "oracle." + oracle.Status
	action := n.mapAction(eventType)
	severity := n.calculateOracleSeverity(oracle)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     oracle.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: oracle.OracleType,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("intent:%s", oracle.IntentID),
		Outcome:  n.determineOracleOutcome(oracle),
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   oracle.OracleType,
			Name: oracle.OracleType,
		},

		Metadata: map[string]any{
			"fie_oracle_id":     oracle.ID,
			"fie_intent_id":     oracle.IntentID,
			"fie_oracle_type":   oracle.OracleType,
			"fie_request_id":    oracle.RequestID,
			"fie_oracle_status": oracle.Status,
			"fie_dispute_id":    oracle.DisputeID,
		},

		Raw: oracle.Query,
	}

	return event, nil
}

// NormalizeSecurity converts a security event to a canonical event.
func (n *Normalizer) NormalizeSecurity(sec *SecurityEvent) (*schema.Event, error) {
	eventType := "security." + sec.EventType
	action := n.mapAction(eventType)
	severity := n.mapSecuritySeverity(sec.Severity)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     sec.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: sec.IntentID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("intent:%s", sec.IntentID),
		Outcome:  schema.OutcomeFailure,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   sec.ActorID,
			Name: sec.ActorID,
		},

		Metadata: map[string]any{
			"fie_security_id":   sec.ID,
			"fie_intent_id":     sec.IntentID,
			"fie_event_type":    sec.EventType,
			"fie_severity":      sec.Severity,
		},

		Raw: sec.Description,
	}

	return event, nil
}

// mapAction maps an event type to a canonical action.
func (n *Normalizer) mapAction(eventType string) string {
	if action, ok := ActionMappings[eventType]; ok {
		return action
	}
	return "fie.event." + eventType
}

// calculateIntentSeverity determines severity based on intent characteristics.
func (n *Normalizer) calculateIntentSeverity(intent *Intent, eventType string) int {
	switch eventType {
	case "intent.activated":
		return 5 // Important lifecycle event
	case "intent.sunset":
		return 4
	case "intent.modified":
		return 6 // Modifications need attention
	default:
		return 3
	}
}

// calculateTriggerSeverity determines severity for trigger events.
func (n *Normalizer) calculateTriggerSeverity(trigger *TriggerEvent) int {
	switch trigger.Status {
	case "rejected":
		return 7
	case "expired":
		return 5
	case "validated":
		if trigger.Confidence < 0.95 {
			return 6 // Low confidence validation
		}
		return 4
	default:
		return 3
	}
}

// calculateExecutionSeverity determines severity for execution events.
func (n *Normalizer) calculateExecutionSeverity(exec *ExecutionEvent) int {
	if exec.Outcome == "blocked" {
		if exec.BlockedReason == "political_content" {
			return 8
		}
		return 7
	}
	if exec.ConfidenceScore < 0.95 {
		return 6
	}
	if exec.Outcome == "failure" {
		return 7
	}
	return 3
}

// calculateIPTokenSeverity determines severity for IP token events.
func (n *Normalizer) calculateIPTokenSeverity(token *IPToken, eventType string) int {
	switch eventType {
	case "ip.token.revoked":
		return 7
	case "ip.token.transferred":
		return 5
	case "ip.token.public_domain":
		return 4
	default:
		return 3
	}
}

// calculateOracleSeverity determines severity for oracle events.
func (n *Normalizer) calculateOracleSeverity(oracle *OracleEvent) int {
	switch oracle.Status {
	case "disputed":
		return 7
	case "timeout":
		return 6
	default:
		return 3
	}
}

// mapSecuritySeverity maps security severity string to numeric.
func (n *Normalizer) mapSecuritySeverity(severity string) int {
	switch severity {
	case "critical":
		return 9
	case "high":
		return 7
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 4
	}
}

// determineIntentOutcome determines outcome for intent events.
func (n *Normalizer) determineIntentOutcome(intent *Intent, eventType string) schema.Outcome {
	switch intent.Status {
	case "sunset", "completed":
		return schema.OutcomeSuccess
	case "archived":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// determineTriggerOutcome determines outcome for trigger events.
func (n *Normalizer) determineTriggerOutcome(trigger *TriggerEvent) schema.Outcome {
	switch trigger.Status {
	case "validated":
		return schema.OutcomeSuccess
	case "rejected", "expired":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// determineExecutionOutcome determines outcome for execution events.
func (n *Normalizer) determineExecutionOutcome(exec *ExecutionEvent) schema.Outcome {
	switch exec.Outcome {
	case "success":
		return schema.OutcomeSuccess
	case "failure", "blocked":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// determineOracleOutcome determines outcome for oracle events.
func (n *Normalizer) determineOracleOutcome(oracle *OracleEvent) schema.Outcome {
	switch oracle.Status {
	case "fulfilled":
		return schema.OutcomeSuccess
	case "disputed", "timeout":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}
