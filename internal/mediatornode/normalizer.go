package mediatornode

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

// Normalizer converts Mediator Node events to canonical schema.
type Normalizer struct {
	config NormalizerConfig
}

// NewNormalizer creates a new normalizer with the given configuration.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	return &Normalizer{config: cfg}
}

// NormalizeAlignment converts an Alignment to a canonical schema Event.
func (n *Normalizer) NormalizeAlignment(alignment *Alignment) (*schema.Event, error) {
	action := fmt.Sprintf("mn.alignment.%s", alignment.Status)
	severity := n.calculateAlignmentSeverity(alignment)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     alignment.ProposedAt,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "mediator-node",
			Host:       n.config.SourceHost,
			InstanceID: alignment.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   alignment.MediatorID,
			Name: fmt.Sprintf("mediator-%s", alignment.MediatorID),
		},

		Action:   action,
		Target:   fmt.Sprintf("offer:%s,request:%s", alignment.OfferIntentID, alignment.RequestIntentID),
		Outcome:  n.mapAlignmentOutcome(alignment.Status),
		Severity: severity,

		Metadata: map[string]any{
			"mn_alignment_id":      alignment.ID,
			"mn_offer_intent_id":   alignment.OfferIntentID,
			"mn_request_intent_id": alignment.RequestIntentID,
			"mn_status":            alignment.Status,
			"mn_confidence":        alignment.Confidence,
			"mn_mediator_id":       alignment.MediatorID,
			"mn_model_hash":        alignment.ModelHash,
		},
	}

	return event, nil
}

// NormalizeNegotiation converts a NegotiationSession to a canonical schema Event.
func (n *Normalizer) NormalizeNegotiation(negotiation *NegotiationSession) (*schema.Event, error) {
	action := fmt.Sprintf("mn.negotiation.%s", negotiation.Status)
	severity := n.calculateNegotiationSeverity(negotiation)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     negotiation.StartedAt,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "mediator-node",
			Host:       n.config.SourceHost,
			InstanceID: negotiation.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorSystem,
			ID:   "negotiation-engine",
		},

		Action:   action,
		Target:   fmt.Sprintf("alignment:%s", negotiation.AlignmentID),
		Outcome:  n.mapNegotiationOutcome(negotiation.Status),
		Severity: severity,

		Metadata: map[string]any{
			"mn_negotiation_id": negotiation.ID,
			"mn_alignment_id":   negotiation.AlignmentID,
			"mn_participants":   negotiation.Participants,
			"mn_status":         negotiation.Status,
			"mn_rounds":         negotiation.Rounds,
			"mn_current_round":  negotiation.CurrentRound,
		},
	}

	if negotiation.Outcome != "" {
		event.Metadata["mn_outcome"] = negotiation.Outcome
	}
	if negotiation.SettlementID != "" {
		event.Metadata["mn_settlement_id"] = negotiation.SettlementID
	}

	return event, nil
}

// NormalizeSettlement converts a Settlement to a canonical schema Event.
func (n *Normalizer) NormalizeSettlement(settlement *Settlement) (*schema.Event, error) {
	action := fmt.Sprintf("mn.settlement.%s", settlement.Status)
	severity := 4

	if settlement.Status == "challenged" {
		severity = 7
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     settlement.SettledAt,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "mediator-node",
			Host:       n.config.SourceHost,
			InstanceID: settlement.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorSystem,
			ID:   "settlement-engine",
		},

		Action:   action,
		Target:   fmt.Sprintf("negotiation:%s", settlement.NegotiationID),
		Outcome:  n.mapSettlementOutcome(settlement.Status),
		Severity: severity,

		Metadata: map[string]any{
			"mn_settlement_id":  settlement.ID,
			"mn_negotiation_id": settlement.NegotiationID,
			"mn_status":         settlement.Status,
			"mn_chain_entry_id": settlement.ChainEntryID,
		},
	}

	return event, nil
}

// NormalizeMediatorEvent converts a MediatorEvent to a canonical schema Event.
func (n *Normalizer) NormalizeMediatorEvent(medEvent *MediatorEvent) (*schema.Event, error) {
	action := fmt.Sprintf("mn.event.%s", medEvent.EventType)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     medEvent.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "mediator-node",
			Host:       n.config.SourceHost,
			InstanceID: medEvent.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   medEvent.MediatorID,
			Name: fmt.Sprintf("mediator-%s", medEvent.MediatorID),
		},

		Action:   action,
		Target:   medEvent.RelatedID,
		Outcome:  schema.OutcomeUnknown,
		Severity: 3,

		Metadata: map[string]any{
			"mn_event_id":    medEvent.ID,
			"mn_event_type":  medEvent.EventType,
			"mn_mediator_id": medEvent.MediatorID,
			"mn_description": medEvent.Description,
		},
	}

	if medEvent.RelatedID != "" {
		event.Metadata["mn_related_id"] = medEvent.RelatedID
	}

	return event, nil
}

// NormalizeReputationEvent converts a ReputationEvent to a canonical schema Event.
func (n *Normalizer) NormalizeReputationEvent(repEvent *ReputationEvent) (*schema.Event, error) {
	action := fmt.Sprintf("mn.reputation.%s", repEvent.ChangeType)
	severity := 3

	if repEvent.ChangeType == "decrease" && repEvent.Amount > 10 {
		severity = 6
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     repEvent.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "mediator-node",
			Host:       n.config.SourceHost,
			InstanceID: repEvent.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   repEvent.MediatorID,
			Name: fmt.Sprintf("mediator-%s", repEvent.MediatorID),
		},

		Action:   action,
		Target:   fmt.Sprintf("mediator:%s", repEvent.MediatorID),
		Outcome:  schema.OutcomeSuccess,
		Severity: severity,

		Metadata: map[string]any{
			"mn_reputation_id": repEvent.ID,
			"mn_mediator_id":   repEvent.MediatorID,
			"mn_change_type":   repEvent.ChangeType,
			"mn_change_amount": repEvent.Amount,
			"mn_reason":        repEvent.Reason,
			"mn_new_score":     repEvent.NewScore,
		},
	}

	return event, nil
}

// NormalizeFlagEvent converts a FlagEvent to a canonical schema Event.
func (n *Normalizer) NormalizeFlagEvent(flagEvent *FlagEvent) (*schema.Event, error) {
	action := fmt.Sprintf("mn.flag.%s", flagEvent.FlagType)
	severity := n.mapFlagSeverity(flagEvent.FlagType)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     flagEvent.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "mediator-node",
			Host:       n.config.SourceHost,
			InstanceID: flagEvent.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   flagEvent.FlaggedBy,
		},

		Action:   action,
		Target:   fmt.Sprintf("intent:%s", flagEvent.IntentID),
		Outcome:  schema.OutcomeFailure,
		Severity: severity,

		Metadata: map[string]any{
			"mn_flag_id":    flagEvent.ID,
			"mn_intent_id":  flagEvent.IntentID,
			"mn_flag_type":  flagEvent.FlagType,
			"mn_flagged_by": flagEvent.FlaggedBy,
			"mn_reason":     flagEvent.Reason,
			"mn_action":     flagEvent.Action,
		},
	}

	return event, nil
}

// calculateAlignmentSeverity determines severity based on alignment characteristics.
func (n *Normalizer) calculateAlignmentSeverity(alignment *Alignment) int {
	if alignment.Status == "rejected" {
		return 5
	}
	if alignment.Confidence < 0.5 {
		return 4
	}
	return 3
}

// calculateNegotiationSeverity determines severity based on negotiation characteristics.
func (n *Normalizer) calculateNegotiationSeverity(negotiation *NegotiationSession) int {
	switch negotiation.Status {
	case "failed":
		return 5
	case "timeout":
		return 5
	case "completed":
		return 3
	default:
		return 3
	}
}

// mapAlignmentOutcome maps alignment status to outcome.
func (n *Normalizer) mapAlignmentOutcome(status string) schema.Outcome {
	switch status {
	case "accepted":
		return schema.OutcomeSuccess
	case "rejected", "expired":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// mapNegotiationOutcome maps negotiation status to outcome.
func (n *Normalizer) mapNegotiationOutcome(status string) schema.Outcome {
	switch status {
	case "completed":
		return schema.OutcomeSuccess
	case "failed", "timeout":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// mapSettlementOutcome maps settlement status to outcome.
func (n *Normalizer) mapSettlementOutcome(status string) schema.Outcome {
	switch status {
	case "confirmed", "finalized":
		return schema.OutcomeSuccess
	case "challenged":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// mapFlagSeverity maps flag type to severity.
func (n *Normalizer) mapFlagSeverity(flagType string) int {
	switch flagType {
	case "prohibited":
		return 8
	case "coercive":
		return 7
	case "spam":
		return 5
	case "vague":
		return 4
	default:
		return 5
	}
}
