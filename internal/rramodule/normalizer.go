package rramodule

import (
	"boundary-siem/internal/schema"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// NormalizerConfig holds configuration for the normalizer.
type NormalizerConfig struct {
	SourceProduct string
	SourceHost    string
	TenantID      string
}

// Normalizer converts RRA-Module events to canonical SIEM events.
type Normalizer struct {
	sourceProduct   string
	sourceHost      string
	defaultTenantID string
}

// NewNormalizer creates a new RRA-Module normalizer.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	product := cfg.SourceProduct
	if product == "" {
		product = "rramodule"
	}
	return &Normalizer{
		sourceProduct:   product,
		sourceHost:      cfg.SourceHost,
		defaultTenantID: cfg.TenantID,
	}
}

// outcomeFromBool converts a success boolean to schema.Outcome.
func rraOutcomeFromBool(success bool) schema.Outcome {
	if success {
		return schema.OutcomeSuccess
	}
	return schema.OutcomeFailure
}

// NormalizeIngestionEvent converts an ingestion event to a canonical event.
func (n *Normalizer) NormalizeIngestionEvent(event *IngestionEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("ingestion event is nil")
	}

	severity := 3
	if !event.Success {
		severity = 6
	}

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     event.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: event.ID,
		},
		Action:   fmt.Sprintf("rra.ingestion.%s", event.EventType),
		Target:   fmt.Sprintf("agent:%s", event.AgentID),
		Outcome:  rraOutcomeFromBool(event.Success),
		Severity: severity,
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   event.AgentID,
			Name: "rra-agent",
		},
		Metadata: map[string]any{
			"rra_event_id":      event.ID,
			"rra_agent_id":      event.AgentID,
			"rra_event_type":    event.EventType,
			"rra_files_scanned": event.FilesScanned,
			"rra_tokens_used":   event.TokensUsed,
			"rra_success":       event.Success,
			"rra_error":         event.ErrorMessage,
		},
	}, nil
}

// NormalizeNegotiationEvent converts a negotiation event to a canonical event.
func (n *Normalizer) NormalizeNegotiationEvent(event *NegotiationEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("negotiation event is nil")
	}

	severity := 3
	if event.EventType == "rejected" {
		severity = 5
	}

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     event.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: event.ID,
		},
		Action:   fmt.Sprintf("rra.negotiation.%s", event.EventType),
		Target:   fmt.Sprintf("counterparty:%s", event.CounterpartyID),
		Outcome:  schema.OutcomeSuccess,
		Severity: severity,
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   event.AgentID,
			Name: "rra-agent",
		},
		Metadata: map[string]any{
			"rra_event_id":       event.ID,
			"rra_agent_id":       event.AgentID,
			"rra_counterparty":   event.CounterpartyID,
			"rra_event_type":     event.EventType,
			"rra_offer_amount":   event.OfferAmount,
			"rra_license_terms":  event.LicenseTerms,
			"rra_llm_model":      event.LLMModel,
		},
	}, nil
}

// NormalizeContractEvent converts a contract event to a canonical event.
func (n *Normalizer) NormalizeContractEvent(event *ContractEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("contract event is nil")
	}

	severity := 4
	if !event.Success {
		severity = 7
	}
	if event.Value >= 10000 {
		severity = max(severity, 6)
	}

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     event.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: event.ID,
		},
		Action:   fmt.Sprintf("rra.contract.%s", event.EventType),
		Target:   fmt.Sprintf("contract:%s", event.ContractAddress),
		Outcome:  rraOutcomeFromBool(event.Success),
		Severity: severity,
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   event.AgentID,
			Name: "rra-agent",
		},
		Metadata: map[string]any{
			"rra_event_id":         event.ID,
			"rra_agent_id":         event.AgentID,
			"rra_chain_id":         event.ChainID,
			"rra_contract_address": event.ContractAddress,
			"rra_event_type":       event.EventType,
			"rra_tx_hash":          event.TxHash,
			"rra_gas_used":         event.GasUsed,
			"rra_value":            event.Value,
			"rra_success":          event.Success,
		},
	}, nil
}

// NormalizeRevenueEvent converts a revenue event to a canonical event.
func (n *Normalizer) NormalizeRevenueEvent(event *RevenueEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("revenue event is nil")
	}

	severity := 3
	if event.Amount >= 50000 {
		severity = 4
	}

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     event.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: event.ID,
		},
		Action:   fmt.Sprintf("rra.revenue.%s", event.EventType),
		Target:   fmt.Sprintf("recipient:%s", event.Recipient),
		Outcome:  schema.OutcomeSuccess,
		Severity: severity,
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   event.Source,
			Name: "rra-revenue-source",
		},
		Metadata: map[string]any{
			"rra_event_id":   event.ID,
			"rra_agent_id":   event.AgentID,
			"rra_event_type": event.EventType,
			"rra_amount":     event.Amount,
			"rra_currency":   event.Currency,
			"rra_source":     event.Source,
			"rra_recipient":  event.Recipient,
			"rra_tx_hash":    event.TxHash,
		},
	}, nil
}

// NormalizeSecurityEvent converts a security event to a canonical event.
func (n *Normalizer) NormalizeSecurityEvent(event *SecurityEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("security event is nil")
	}

	outcome := schema.OutcomeSuccess
	if event.Blocked {
		outcome = schema.OutcomeUnknown
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

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     event.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: event.ID,
		},
		Action:   fmt.Sprintf("rra.security.%s", event.EventType),
		Target:   fmt.Sprintf("agent:%s", event.AgentID),
		Outcome:  outcome,
		Severity: severity,
		Actor: &schema.Actor{
			Type:      schema.ActorUnknown,
			ID:        event.SourceIP,
			Name:      "external-actor",
			IPAddress: event.SourceIP,
		},
		Metadata: map[string]any{
			"rra_event_id":    event.ID,
			"rra_agent_id":    event.AgentID,
			"rra_event_type":  event.EventType,
			"rra_severity":    event.Severity,
			"rra_description": event.Description,
			"rra_source_ip":   event.SourceIP,
			"rra_blocked":     event.Blocked,
		},
	}, nil
}

// NormalizeGovernanceEvent converts a governance event to a canonical event.
func (n *Normalizer) NormalizeGovernanceEvent(event *GovernanceEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("governance event is nil")
	}

	severity := 4
	if event.EventType == "proposal_executed" {
		severity = 5
	}

	actorID := event.AgentID
	actorName := "rra-agent"
	if event.VoterID != "" {
		actorID = event.VoterID
		actorName = "dao-voter"
	}

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     event.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: event.ID,
		},
		Action:   fmt.Sprintf("rra.governance.%s", event.EventType),
		Target:   fmt.Sprintf("proposal:%s", event.ProposalID),
		Outcome:  schema.OutcomeSuccess,
		Severity: severity,
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   actorID,
			Name: actorName,
		},
		Metadata: map[string]any{
			"rra_event_id":    event.ID,
			"rra_agent_id":    event.AgentID,
			"rra_event_type":  event.EventType,
			"rra_proposal_id": event.ProposalID,
			"rra_voter_id":    event.VoterID,
			"rra_vote_weight": event.VoteWeight,
			"rra_outcome":     event.Outcome,
		},
	}, nil
}
