package ilrmodule

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
		SourceVersion:   "1.5.0",
	}
}

// Normalizer converts ILR-Module events to canonical schema.
type Normalizer struct {
	config NormalizerConfig
}

// NewNormalizer creates a new normalizer with the given configuration.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	return &Normalizer{config: cfg}
}

// NormalizeDispute converts a Dispute to a canonical schema Event.
func (n *Normalizer) NormalizeDispute(dispute *Dispute) (*schema.Event, error) {
	action := n.mapDisputeStatusToAction(dispute.Status)
	severity := n.mapDisputeSeverity(dispute.Severity)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     dispute.FiledAt,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "ilr-module",
			Host:       n.config.SourceHost,
			InstanceID: dispute.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   dispute.Claimant,
			Name: dispute.Claimant,
		},

		Action:   action,
		Target:   fmt.Sprintf("respondent:%s,subject:%s", dispute.Respondent, dispute.Subject),
		Outcome:  n.determineDisputeOutcome(dispute),
		Severity: severity,

		Metadata: map[string]any{
			"ilr_dispute_id":   dispute.ID,
			"ilr_chain_id":     dispute.ChainID,
			"ilr_dispute_type": dispute.DisputeType,
			"ilr_status":       dispute.Status,
			"ilr_severity":     dispute.Severity,
			"ilr_stake_amount": dispute.StakeAmount,
			"ilr_claimant":     dispute.Claimant,
			"ilr_respondent":   dispute.Respondent,
		},
	}

	if dispute.Resolution != nil {
		event.Metadata["ilr_resolution_outcome"] = dispute.Resolution.Outcome
		event.Metadata["ilr_resolution_award"] = dispute.Resolution.Award
	}

	if dispute.L3BatchID != "" {
		event.Metadata["ilr_l3_batch_id"] = dispute.L3BatchID
	}

	return event, nil
}

// NormalizeProposal converts a Proposal to a canonical schema Event.
func (n *Normalizer) NormalizeProposal(proposal *Proposal) (*schema.Event, error) {
	action := fmt.Sprintf("ilr.proposal.%s", proposal.Status)
	severity := 4

	if proposal.Status == "rejected" {
		severity = 5
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     proposal.ProposedAt,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "ilr-module",
			Host:       n.config.SourceHost,
			InstanceID: proposal.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   proposal.ProposerModel,
			Name: fmt.Sprintf("llm-%s", proposal.ProposerModel),
		},

		Action:   action,
		Target:   fmt.Sprintf("dispute:%s", proposal.DisputeID),
		Outcome:  n.mapProposalOutcome(proposal.Status),
		Severity: severity,

		Metadata: map[string]any{
			"ilr_proposal_id":    proposal.ID,
			"ilr_dispute_id":     proposal.DisputeID,
			"ilr_proposer_model": proposal.ProposerModel,
			"ilr_confidence":     proposal.Confidence,
			"ilr_status":         proposal.Status,
		},
	}

	return event, nil
}

// NormalizeComplianceEvent converts a ComplianceEvent to a canonical schema Event.
func (n *Normalizer) NormalizeComplianceEvent(compEvent *ComplianceEvent) (*schema.Event, error) {
	action := fmt.Sprintf("ilr.compliance.%s", compEvent.EventType)

	var outcome schema.Outcome
	var severity int
	if compEvent.Passed {
		outcome = schema.OutcomeSuccess
		severity = 2
	} else {
		outcome = schema.OutcomeFailure
		severity = 7
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     compEvent.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "ilr-module",
			Host:       n.config.SourceHost,
			InstanceID: compEvent.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   compEvent.Actor,
			Name: compEvent.Actor,
		},

		Action:   action,
		Target:   fmt.Sprintf("dispute:%s", compEvent.DisputeID),
		Outcome:  outcome,
		Severity: severity,

		Metadata: map[string]any{
			"ilr_event_id":   compEvent.ID,
			"ilr_event_type": compEvent.EventType,
			"ilr_dispute_id": compEvent.DisputeID,
			"ilr_passed":     compEvent.Passed,
			"ilr_details":    compEvent.Details,
		},
	}

	return event, nil
}

// NormalizeL3BatchEvent converts a L3BatchEvent to a canonical schema Event.
func (n *Normalizer) NormalizeL3BatchEvent(batch *L3BatchEvent) (*schema.Event, error) {
	action := fmt.Sprintf("ilr.l3.%s", batch.Status)
	severity := 3

	if batch.Status == "challenged" {
		severity = 8
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     batch.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "ilr-module",
			Host:       n.config.SourceHost,
			InstanceID: batch.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorSystem,
			ID:   "l3-rollup",
		},

		Action:   action,
		Target:   fmt.Sprintf("batch:%s", batch.BatchID),
		Outcome:  n.mapL3Outcome(batch.Status),
		Severity: severity,

		Metadata: map[string]any{
			"ilr_batch_id":        batch.BatchID,
			"ilr_dispute_count":   batch.DisputeCount,
			"ilr_status":          batch.Status,
			"ilr_state_root":      batch.StateRoot,
			"ilr_fraud_proof_end": batch.FraudProofEnd.Format(time.RFC3339),
		},
	}

	return event, nil
}

// NormalizeOracleEvent converts an OracleEvent to a canonical schema Event.
func (n *Normalizer) NormalizeOracleEvent(oracle *OracleEvent) (*schema.Event, error) {
	action := fmt.Sprintf("ilr.oracle.%s", oracle.RequestType)
	severity := 4

	if oracle.Status == "failed" || oracle.Status == "disputed" {
		severity = 7
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     oracle.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "ilr-module",
			Host:       n.config.SourceHost,
			InstanceID: oracle.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   oracle.OracleType,
			Name: fmt.Sprintf("oracle-%s", oracle.OracleType),
		},

		Action:   action,
		Target:   fmt.Sprintf("dispute:%s", oracle.DisputeID),
		Outcome:  n.mapOracleOutcome(oracle.Status),
		Severity: severity,

		Metadata: map[string]any{
			"ilr_oracle_id":     oracle.ID,
			"ilr_oracle_type":   oracle.OracleType,
			"ilr_dispute_id":    oracle.DisputeID,
			"ilr_request_type":  oracle.RequestType,
			"ilr_oracle_status": oracle.Status,
		},
	}

	if oracle.Response != "" {
		event.Metadata["ilr_oracle_response"] = oracle.Response
	}

	return event, nil
}

// mapDisputeStatusToAction maps dispute status to canonical action.
func (n *Normalizer) mapDisputeStatusToAction(status string) string {
	switch status {
	case "open":
		return "ilr.dispute.filed"
	case "mediation":
		return "ilr.dispute.mediation"
	case "arbitration":
		return "ilr.dispute.arbitration"
	case "resolved":
		return "ilr.dispute.resolved"
	case "dismissed":
		return "ilr.dispute.dismissed"
	default:
		return fmt.Sprintf("ilr.dispute.%s", status)
	}
}

// mapDisputeSeverity maps dispute severity to canonical severity.
func (n *Normalizer) mapDisputeSeverity(severity string) int {
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

// determineDisputeOutcome determines the outcome based on dispute state.
func (n *Normalizer) determineDisputeOutcome(dispute *Dispute) schema.Outcome {
	switch dispute.Status {
	case "resolved":
		return schema.OutcomeSuccess
	case "dismissed":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// mapProposalOutcome maps proposal status to outcome.
func (n *Normalizer) mapProposalOutcome(status string) schema.Outcome {
	switch status {
	case "accepted":
		return schema.OutcomeSuccess
	case "rejected":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// mapL3Outcome maps L3 batch status to outcome.
func (n *Normalizer) mapL3Outcome(status string) schema.Outcome {
	switch status {
	case "finalized":
		return schema.OutcomeSuccess
	case "challenged":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// mapOracleOutcome maps oracle status to outcome.
func (n *Normalizer) mapOracleOutcome(status string) schema.Outcome {
	switch status {
	case "success", "verified":
		return schema.OutcomeSuccess
	case "failed", "disputed":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}
