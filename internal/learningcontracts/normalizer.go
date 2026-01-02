package learningcontracts

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/schema"
)

// NormalizerConfig holds configuration for the normalizer.
type NormalizerConfig struct {
	DefaultTenantID string `yaml:"default_tenant_id"`
	SourceHost      string `yaml:"source_host"`
	SourceVersion   string `yaml:"source_version"`
}

// DefaultNormalizerConfig returns the default normalizer configuration.
func DefaultNormalizerConfig() NormalizerConfig {
	return NormalizerConfig{
		DefaultTenantID: "default",
		SourceHost:      "localhost",
		SourceVersion:   "1.0.0",
	}
}

// Normalizer converts Learning Contracts events to canonical schema.
type Normalizer struct {
	config NormalizerConfig
}

// NewNormalizer creates a new normalizer with the given configuration.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	return &Normalizer{config: cfg}
}

// NormalizeContract converts a Contract to a canonical schema Event.
func (n *Normalizer) NormalizeContract(contract *Contract) (*schema.Event, error) {
	action := n.mapContractStatusToAction(contract.Status)
	severity := n.calculateContractSeverity(contract)

	timestamp := contract.CreatedAt
	if contract.ActivatedAt != nil {
		timestamp = *contract.ActivatedAt
	}
	if contract.RevokedAt != nil {
		timestamp = *contract.RevokedAt
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "learning-contracts",
			Host:       n.config.SourceHost,
			InstanceID: contract.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   contract.UserID,
			Name: contract.UserID,
		},

		Action:   action,
		Target:   fmt.Sprintf("agent:%s", contract.AgentID),
		Outcome:  n.determineContractOutcome(contract),
		Severity: severity,

		Metadata: map[string]any{
			"lc_contract_id":   contract.ID,
			"lc_agent_id":      contract.AgentID,
			"lc_user_id":       contract.UserID,
			"lc_contract_type": contract.ContractType,
			"lc_status":        contract.Status,
			"lc_domains":       contract.Scope.Domains,
		},
	}

	if contract.RevokedBy != "" {
		event.Metadata["lc_revoked_by"] = contract.RevokedBy
		event.Metadata["lc_revoke_reason"] = contract.RevokeReason
	}

	return event, nil
}

// NormalizeEnforcementEvent converts an EnforcementEvent to a canonical schema Event.
func (n *Normalizer) NormalizeEnforcementEvent(enforcement *EnforcementEvent) (*schema.Event, error) {
	action := fmt.Sprintf("lc.enforcement.%s", enforcement.GateType)

	var outcome schema.Outcome
	var severity int
	if enforcement.Allowed {
		outcome = schema.OutcomeSuccess
		severity = 2
	} else {
		outcome = schema.OutcomeFailure
		severity = 6
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     enforcement.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "learning-contracts",
			Host:       n.config.SourceHost,
			InstanceID: enforcement.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   enforcement.AgentID,
			Name: fmt.Sprintf("agent-%s", enforcement.AgentID),
		},

		Action:   action,
		Target:   fmt.Sprintf("contract:%s", enforcement.ContractID),
		Outcome:  outcome,
		Severity: severity,

		Metadata: map[string]any{
			"lc_event_id":    enforcement.ID,
			"lc_contract_id": enforcement.ContractID,
			"lc_agent_id":    enforcement.AgentID,
			"lc_gate_type":   enforcement.GateType,
			"lc_operation":   enforcement.Operation,
			"lc_allowed":     enforcement.Allowed,
			"lc_reason":      enforcement.Reason,
		},
	}

	if enforcement.DataHash != "" {
		event.Metadata["lc_data_hash"] = enforcement.DataHash
	}

	return event, nil
}

// NormalizeStateChange converts a ContractStateChange to a canonical schema Event.
func (n *Normalizer) NormalizeStateChange(change *ContractStateChange) (*schema.Event, error) {
	action := fmt.Sprintf("lc.state.%s", change.ToState)
	severity := n.calculateStateChangeSeverity(change)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     change.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "learning-contracts",
			Host:       n.config.SourceHost,
			InstanceID: change.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   change.ChangedBy,
			Name: change.ChangedBy,
		},

		Action:   action,
		Target:   fmt.Sprintf("contract:%s", change.ContractID),
		Outcome:  schema.OutcomeSuccess,
		Severity: severity,

		Metadata: map[string]any{
			"lc_change_id":   change.ID,
			"lc_contract_id": change.ContractID,
			"lc_from_state":  change.FromState,
			"lc_to_state":    change.ToState,
			"lc_changed_by":  change.ChangedBy,
			"lc_reason":      change.Reason,
			"lc_audit_hash":  change.AuditHash,
		},
	}

	return event, nil
}

// NormalizeViolation converts a ViolationEvent to a canonical schema Event.
func (n *Normalizer) NormalizeViolation(violation *ViolationEvent) (*schema.Event, error) {
	action := fmt.Sprintf("lc.violation.%s", violation.ViolationType)
	severity := n.mapViolationSeverity(violation.Severity)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     violation.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "learning-contracts",
			Host:       n.config.SourceHost,
			InstanceID: violation.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   violation.AgentID,
			Name: fmt.Sprintf("agent-%s", violation.AgentID),
		},

		Action:   action,
		Target:   fmt.Sprintf("contract:%s", violation.ContractID),
		Outcome:  schema.OutcomeFailure,
		Severity: severity,

		Metadata: map[string]any{
			"lc_violation_id":   violation.ID,
			"lc_contract_id":    violation.ContractID,
			"lc_agent_id":       violation.AgentID,
			"lc_violation_type": violation.ViolationType,
			"lc_description":    violation.Description,
			"lc_severity":       violation.Severity,
		},
	}

	if violation.Remediation != "" {
		event.Metadata["lc_remediation"] = violation.Remediation
	}

	return event, nil
}

// mapContractStatusToAction maps contract status to canonical action.
func (n *Normalizer) mapContractStatusToAction(status string) string {
	switch status {
	case "draft":
		return "lc.contract.drafted"
	case "pending_review":
		return "lc.contract.submitted"
	case "active":
		return "lc.contract.activated"
	case "revoked":
		return "lc.contract.revoked"
	case "expired":
		return "lc.contract.expired"
	default:
		return fmt.Sprintf("lc.contract.%s", status)
	}
}

// calculateContractSeverity determines severity based on contract characteristics.
func (n *Normalizer) calculateContractSeverity(contract *Contract) int {
	// Revocations are significant
	if contract.Status == "revoked" {
		return 6
	}

	// Strategic contracts are high-trust
	if contract.ContractType == "strategic" {
		return 5
	}

	// Prohibited contracts are notable
	if contract.ContractType == "prohibited" {
		return 4
	}

	return 3
}

// determineContractOutcome determines the outcome based on contract state.
func (n *Normalizer) determineContractOutcome(contract *Contract) schema.Outcome {
	switch contract.Status {
	case "active":
		return schema.OutcomeSuccess
	case "revoked", "expired":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// calculateStateChangeSeverity determines severity based on state transition.
func (n *Normalizer) calculateStateChangeSeverity(change *ContractStateChange) int {
	// Revocation is significant
	if change.ToState == "revoked" {
		return 6
	}

	// Activation is notable
	if change.ToState == "active" {
		return 4
	}

	return 3
}

// mapViolationSeverity maps violation severity to canonical severity.
func (n *Normalizer) mapViolationSeverity(severity string) int {
	switch severity {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 6
	case "low":
		return 4
	default:
		return 5
	}
}
