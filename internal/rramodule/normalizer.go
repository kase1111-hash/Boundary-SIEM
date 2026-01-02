package rramodule

import (
	"boundary-siem/internal/core/schema"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Normalizer converts RRA-Module events to canonical SIEM events.
type Normalizer struct{}

// NewNormalizer creates a new RRA-Module normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// NormalizeIngestionEvent converts an ingestion event to a canonical event.
func (n *Normalizer) NormalizeIngestionEvent(event IngestionEvent) schema.CanonicalEvent {
	outcome := "success"
	if !event.Success {
		outcome = "failure"
	}

	severity := 3
	if !event.Success {
		severity = 6
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.AgentID,
		Action:    fmt.Sprintf("rra.ingestion.%s", event.EventType),
		Target:    event.AgentID,
		Outcome:   outcome,
		Severity:  severity,
		Metadata: map[string]any{
			"rra_event_id":      event.ID,
			"rra_agent_id":      event.AgentID,
			"rra_event_type":    event.EventType,
			"rra_files_scanned": event.FilesScanned,
			"rra_tokens_used":   event.TokensUsed,
			"rra_success":       event.Success,
			"rra_error":         event.ErrorMessage,
			"source":            "rramodule",
		},
		Source:    "rramodule",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeNegotiationEvent converts a negotiation event to a canonical event.
func (n *Normalizer) NormalizeNegotiationEvent(event NegotiationEvent) schema.CanonicalEvent {
	severity := 3
	if event.EventType == "rejected" {
		severity = 5
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.AgentID,
		Action:    fmt.Sprintf("rra.negotiation.%s", event.EventType),
		Target:    event.CounterpartyID,
		Outcome:   "success",
		Severity:  severity,
		Metadata: map[string]any{
			"rra_event_id":       event.ID,
			"rra_agent_id":       event.AgentID,
			"rra_counterparty":   event.CounterpartyID,
			"rra_event_type":     event.EventType,
			"rra_offer_amount":   event.OfferAmount,
			"rra_license_terms":  event.LicenseTerms,
			"rra_llm_model":      event.LLMModel,
			"source":             "rramodule",
		},
		Source:    "rramodule",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeContractEvent converts a contract event to a canonical event.
func (n *Normalizer) NormalizeContractEvent(event ContractEvent) schema.CanonicalEvent {
	outcome := "success"
	if !event.Success {
		outcome = "failure"
	}

	severity := 4
	if !event.Success {
		severity = 7
	}
	if event.Value >= 10000 {
		severity = max(severity, 6)
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.AgentID,
		Action:    fmt.Sprintf("rra.contract.%s", event.EventType),
		Target:    event.ContractAddress,
		Outcome:   outcome,
		Severity:  severity,
		Metadata: map[string]any{
			"rra_event_id":        event.ID,
			"rra_agent_id":        event.AgentID,
			"rra_chain_id":        event.ChainID,
			"rra_contract_address": event.ContractAddress,
			"rra_event_type":      event.EventType,
			"rra_tx_hash":         event.TxHash,
			"rra_gas_used":        event.GasUsed,
			"rra_value":           event.Value,
			"rra_success":         event.Success,
			"source":              "rramodule",
		},
		Source:    "rramodule",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeRevenueEvent converts a revenue event to a canonical event.
func (n *Normalizer) NormalizeRevenueEvent(event RevenueEvent) schema.CanonicalEvent {
	severity := 3
	if event.Amount >= 50000 {
		severity = 4
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.Source,
		Action:    fmt.Sprintf("rra.revenue.%s", event.EventType),
		Target:    event.Recipient,
		Outcome:   "success",
		Severity:  severity,
		Metadata: map[string]any{
			"rra_event_id":   event.ID,
			"rra_agent_id":   event.AgentID,
			"rra_event_type": event.EventType,
			"rra_amount":     event.Amount,
			"rra_currency":   event.Currency,
			"rra_source":     event.Source,
			"rra_recipient":  event.Recipient,
			"rra_tx_hash":    event.TxHash,
			"source":         "rramodule",
		},
		Source:    "rramodule",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeSecurityEvent converts a security event to a canonical event.
func (n *Normalizer) NormalizeSecurityEvent(event SecurityEvent) schema.CanonicalEvent {
	outcome := "success"
	if event.Blocked {
		outcome = "blocked"
	}

	severity := 5
	switch event.Severity {
	case "critical":
		severity = 9
	case "high":
		severity = 7
	case "medium":
		severity = 5
	case "low":
		severity = 3
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.SourceIP,
		Action:    fmt.Sprintf("rra.security.%s", event.EventType),
		Target:    event.AgentID,
		Outcome:   outcome,
		Severity:  severity,
		Metadata: map[string]any{
			"rra_event_id":    event.ID,
			"rra_agent_id":    event.AgentID,
			"rra_event_type":  event.EventType,
			"rra_severity":    event.Severity,
			"rra_description": event.Description,
			"rra_source_ip":   event.SourceIP,
			"rra_blocked":     event.Blocked,
			"source":          "rramodule",
		},
		Source:    "rramodule",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeGovernanceEvent converts a governance event to a canonical event.
func (n *Normalizer) NormalizeGovernanceEvent(event GovernanceEvent) schema.CanonicalEvent {
	severity := 4
	if event.EventType == "proposal_executed" {
		severity = 5
	}

	actor := event.AgentID
	if event.VoterID != "" {
		actor = event.VoterID
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     actor,
		Action:    fmt.Sprintf("rra.governance.%s", event.EventType),
		Target:    event.ProposalID,
		Outcome:   "success",
		Severity:  severity,
		Metadata: map[string]any{
			"rra_event_id":    event.ID,
			"rra_agent_id":    event.AgentID,
			"rra_event_type":  event.EventType,
			"rra_proposal_id": event.ProposalID,
			"rra_voter_id":    event.VoterID,
			"rra_vote_weight": event.VoteWeight,
			"rra_outcome":     event.Outcome,
			"source":          "rramodule",
		},
		Source:    "rramodule",
		CreatedAt: time.Now().UTC(),
	}
}
