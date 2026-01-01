package natlangchain

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/schema"
)

// ActionMappings maps NatLangChain event types to canonical action names.
var ActionMappings = map[string]string{
	// Entry events
	"entry.created":    "nlc.entry.created",
	"entry.validated":  "nlc.entry.validated",
	"entry.rejected":   "nlc.entry.rejected",
	"entry.modified":   "nlc.entry.modified",

	// Block events
	"block.mined":      "nlc.block.mined",
	"block.validated":  "nlc.block.validated",
	"block.rejected":   "nlc.block.rejected",

	// Dispute events
	"dispute.filed":    "nlc.dispute.filed",
	"dispute.resolved": "nlc.dispute.resolved",
	"dispute.escalated": "nlc.dispute.escalated",
	"dispute.dismissed": "nlc.dispute.dismissed",

	// Contract events
	"contract.created": "nlc.contract.created",
	"contract.matched": "nlc.contract.matched",
	"contract.completed": "nlc.contract.completed",
	"contract.cancelled": "nlc.contract.cancelled",

	// Negotiation events
	"negotiation.started": "nlc.negotiation.started",
	"negotiation.round":   "nlc.negotiation.round",
	"negotiation.completed": "nlc.negotiation.completed",
	"negotiation.failed":  "nlc.negotiation.failed",
	"negotiation.timeout": "nlc.negotiation.timeout",

	// Validation/Consensus events
	"validation.paraphrase": "nlc.validation.paraphrase",
	"validation.debate":     "nlc.validation.debate",
	"validation.consensus":  "nlc.validation.consensus",
	"validation.rejection":  "nlc.validation.rejection",

	// Semantic events
	"semantic.drift.detected": "nlc.semantic.drift",
	"semantic.drift.critical": "nlc.semantic.drift.critical",

	// Security events
	"security.adversarial":    "nlc.security.adversarial",
	"security.manipulation":   "nlc.security.manipulation",
	"security.impersonation":  "nlc.security.impersonation",
}

// Normalizer converts NatLangChain events to canonical SIEM schema.
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

// NewNormalizer creates a new NatLangChain normalizer.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	return &Normalizer{
		defaultTenantID: cfg.DefaultTenantID,
		sourceProduct:   "natlangchain",
		sourceHost:      cfg.SourceHost,
		sourceVersion:   cfg.SourceVersion,
	}
}

// NormalizeEntry converts a NatLangChain entry to a canonical event.
func (n *Normalizer) NormalizeEntry(entry *Entry, eventType string) (*schema.Event, error) {
	action := n.mapAction(eventType)
	severity := n.calculateEntrySeverity(entry, eventType)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     entry.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: entry.ChainID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("entry:%s", entry.ID),
		Outcome:  n.determineEntryOutcome(entry, eventType),
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   entry.AuthorID,
			Name: entry.Author,
		},

		Metadata: map[string]any{
			"nlc_entry_id":     entry.ID,
			"nlc_chain_id":     entry.ChainID,
			"nlc_block_number": entry.BlockNumber,
			"nlc_block_hash":   entry.BlockHash,
			"nlc_content_hash": entry.ContentHash,
			"nlc_entry_type":   entry.EntryType,
			"nlc_validated":    entry.Validated,
			"nlc_validator_id": entry.ValidatorID,
		},

		Raw: entry.Content,
	}

	return event, nil
}

// NormalizeBlock converts a NatLangChain block to a canonical event.
func (n *Normalizer) NormalizeBlock(block *Block, eventType string) (*schema.Event, error) {
	action := n.mapAction(eventType)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     block.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: block.Hash,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("block:%d", block.Number),
		Outcome:  schema.OutcomeSuccess,
		Severity: 2, // Informational

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   block.ValidatorID,
			Name: "validator",
		},

		Metadata: map[string]any{
			"nlc_block_number":   block.Number,
			"nlc_block_hash":     block.Hash,
			"nlc_previous_hash":  block.PreviousHash,
			"nlc_entry_count":    len(block.Entries),
			"nlc_validator_id":   block.ValidatorID,
		},
	}

	return event, nil
}

// NormalizeDispute converts a NatLangChain dispute to a canonical event.
func (n *Normalizer) NormalizeDispute(dispute *Dispute, eventType string) (*schema.Event, error) {
	action := n.mapAction(eventType)
	severity := n.calculateDisputeSeverity(dispute)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     dispute.FiledAt,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: dispute.ID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("entry:%s", dispute.EntryID),
		Outcome:  n.determineDisputeOutcome(dispute),
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   dispute.FiledBy,
			Name: dispute.FiledBy,
		},

		Metadata: map[string]any{
			"nlc_dispute_id":     dispute.ID,
			"nlc_entry_id":       dispute.EntryID,
			"nlc_dispute_status": dispute.Status,
			"nlc_dispute_reason": dispute.Reason,
			"nlc_evidence_count": len(dispute.Evidence),
		},

		Raw: dispute.Reason,
	}

	if dispute.ResolvedAt != nil {
		event.Timestamp = *dispute.ResolvedAt
		event.Metadata["nlc_resolved_by"] = dispute.ResolvedBy
		event.Metadata["nlc_resolution"] = dispute.Resolution
	}

	return event, nil
}

// NormalizeContract converts a NatLangChain contract to a canonical event.
func (n *Normalizer) NormalizeContract(contract *Contract, eventType string) (*schema.Event, error) {
	action := n.mapAction(eventType)

	timestamp := contract.CreatedAt
	if contract.MatchedAt != nil && (eventType == "contract.matched" || eventType == "contract.completed") {
		timestamp = *contract.MatchedAt
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
			InstanceID: contract.ChainID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("contract:%s", contract.ID),
		Outcome:  n.determineContractOutcome(contract),
		Severity: 3,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   contract.Creator,
			Name: contract.Creator,
		},

		Metadata: map[string]any{
			"nlc_contract_id":     contract.ID,
			"nlc_chain_id":        contract.ChainID,
			"nlc_contract_status": contract.Status,
			"nlc_matched_with":    contract.MatchedWith,
		},

		Raw: contract.Content,
	}

	return event, nil
}

// NormalizeNegotiation converts a NatLangChain negotiation to a canonical event.
func (n *Normalizer) NormalizeNegotiation(neg *Negotiation, eventType string) (*schema.Event, error) {
	action := n.mapAction(eventType)
	severity := 3

	if eventType == "negotiation.failed" || eventType == "negotiation.timeout" {
		severity = 5
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     neg.LastActivity,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: neg.ID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("negotiation:%s", neg.ID),
		Outcome:  n.determineNegotiationOutcome(neg),
		Severity: severity,

		Metadata: map[string]any{
			"nlc_negotiation_id":     neg.ID,
			"nlc_participants":       neg.Participants,
			"nlc_participant_count":  len(neg.Participants),
			"nlc_rounds":             neg.Rounds,
			"nlc_negotiation_status": neg.Status,
			"nlc_outcome":            neg.Outcome,
		},
	}

	return event, nil
}

// NormalizeSemanticDrift converts a semantic drift detection to a canonical event.
func (n *Normalizer) NormalizeSemanticDrift(drift *SemanticDrift) (*schema.Event, error) {
	eventType := "semantic.drift.detected"
	if drift.Severity == "critical" {
		eventType = "semantic.drift.critical"
	}
	action := n.mapAction(eventType)

	severity := n.mapDriftSeverity(drift.Severity)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     drift.DetectedAt,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: drift.ValidatorID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("entry:%s", drift.EntryID),
		Outcome:  schema.OutcomeFailure,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   drift.ValidatorID,
			Name: "validator",
		},

		Metadata: map[string]any{
			"nlc_drift_id":         drift.ID,
			"nlc_entry_id":         drift.EntryID,
			"nlc_drift_score":      drift.DriftScore,
			"nlc_drift_severity":   drift.Severity,
			"nlc_original_meaning": drift.OriginalMeaning,
			"nlc_drifted_meaning":  drift.DriftedMeaning,
		},
	}

	return event, nil
}

// NormalizeValidationEvent converts a validation event to a canonical event.
func (n *Normalizer) NormalizeValidationEvent(ve *ValidationEvent) (*schema.Event, error) {
	action := n.mapAction("validation." + ve.EventType)

	outcome := schema.OutcomeSuccess
	severity := 2
	if ve.EventType == "rejection" {
		outcome = schema.OutcomeFailure
		severity = 5
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     ve.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: ve.ValidatorID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("entry:%s", ve.EntryID),
		Outcome:  outcome,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   ve.ValidatorID,
			Name: "validator",
		},

		Metadata: map[string]any{
			"nlc_validation_id":   ve.ID,
			"nlc_entry_id":        ve.EntryID,
			"nlc_validator_id":    ve.ValidatorID,
			"nlc_event_type":      ve.EventType,
			"nlc_confidence":      ve.Confidence,
			"nlc_paraphrase":      ve.Paraphrase,
			"nlc_debate_role":     ve.DebateRole,
			"nlc_debate_message":  ve.DebateMessage,
		},
	}

	return event, nil
}

// mapAction maps an event type to a canonical action.
func (n *Normalizer) mapAction(eventType string) string {
	if action, ok := ActionMappings[eventType]; ok {
		return action
	}
	return "nlc.event." + eventType
}

// calculateEntrySeverity determines severity based on entry characteristics.
func (n *Normalizer) calculateEntrySeverity(entry *Entry, eventType string) int {
	if eventType == "entry.rejected" {
		return 6
	}
	if !entry.Validated && eventType == "entry.created" {
		return 3
	}
	return 2
}

// calculateDisputeSeverity determines severity based on dispute status.
func (n *Normalizer) calculateDisputeSeverity(dispute *Dispute) int {
	switch dispute.Status {
	case "escalated":
		return 7
	case "open":
		return 5
	case "resolved", "dismissed":
		return 3
	default:
		return 4
	}
}

// determineEntryOutcome determines the outcome for an entry event.
func (n *Normalizer) determineEntryOutcome(entry *Entry, eventType string) schema.Outcome {
	if eventType == "entry.rejected" {
		return schema.OutcomeFailure
	}
	if entry.Validated || eventType == "entry.validated" {
		return schema.OutcomeSuccess
	}
	return schema.OutcomeUnknown
}

// determineDisputeOutcome determines the outcome for a dispute event.
func (n *Normalizer) determineDisputeOutcome(dispute *Dispute) schema.Outcome {
	switch dispute.Status {
	case "resolved":
		return schema.OutcomeSuccess
	case "dismissed", "escalated":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// determineContractOutcome determines the outcome for a contract event.
func (n *Normalizer) determineContractOutcome(contract *Contract) schema.Outcome {
	switch contract.Status {
	case "completed", "matched":
		return schema.OutcomeSuccess
	case "cancelled":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// determineNegotiationOutcome determines the outcome for a negotiation event.
func (n *Normalizer) determineNegotiationOutcome(neg *Negotiation) schema.Outcome {
	switch neg.Status {
	case "completed":
		return schema.OutcomeSuccess
	case "failed", "timeout":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// mapDriftSeverity maps drift severity string to numeric severity.
func (n *Normalizer) mapDriftSeverity(severity string) int {
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
