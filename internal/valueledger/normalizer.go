package valueledger

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

// Normalizer converts Value Ledger events to canonical schema.
type Normalizer struct {
	config NormalizerConfig
}

// NewNormalizer creates a new normalizer with the given configuration.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	return &Normalizer{config: cfg}
}

// NormalizeLedgerEntry converts a LedgerEntry to a canonical schema Event.
func (n *Normalizer) NormalizeLedgerEntry(entry *LedgerEntry) (*schema.Event, error) {
	action := n.mapEntryTypeToAction(entry.EntryType)
	severity := n.calculateSeverity(entry)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     entry.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "value-ledger",
			Host:       n.config.SourceHost,
			InstanceID: entry.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   entry.AgentID,
			Name: fmt.Sprintf("agent-%s", entry.AgentID),
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", entry.SessionID),
		Outcome:  n.determineOutcome(entry),
		Severity: severity,

		Metadata: map[string]any{
			"vl_entry_id":     entry.ID,
			"vl_entry_type":   entry.EntryType,
			"vl_session_id":   entry.SessionID,
			"vl_total_value":  entry.TotalValue,
			"vl_content_hash": entry.ContentHash,
			"vl_value_time":   entry.Value.Time,
			"vl_value_effort": entry.Value.Effort,
			"vl_value_novelty": entry.Value.Novelty,
			"vl_revoked":      entry.Revoked,
		},
	}

	if entry.Revoked {
		event.Metadata["vl_revoked_reason"] = entry.RevokedReason
	}

	return event, nil
}

// NormalizeSecurityEvent converts a SecurityEvent to a canonical schema Event.
func (n *Normalizer) NormalizeSecurityEvent(secEvent *SecurityEvent) (*schema.Event, error) {
	action := fmt.Sprintf("vl.security.%s", secEvent.EventType)
	severity := n.mapSecuritySeverity(secEvent.Severity)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     secEvent.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "value-ledger",
			Host:       n.config.SourceHost,
			InstanceID: secEvent.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   secEvent.AgentID,
			Name: fmt.Sprintf("agent-%s", secEvent.AgentID),
		},

		Action:   action,
		Target:   "value-ledger",
		Outcome:  schema.OutcomeUnknown,
		Severity: severity,

		Metadata: map[string]any{
			"vl_event_id":          secEvent.ID,
			"vl_security_type":     secEvent.EventType,
			"vl_security_severity": secEvent.Severity,
			"vl_description":       secEvent.Description,
		},
	}

	// Copy additional metadata
	for k, v := range secEvent.Metadata {
		event.Metadata["vl_"+k] = v
	}

	return event, nil
}

// NormalizeMerkleProof converts a MerkleProof verification to a canonical schema Event.
func (n *Normalizer) NormalizeMerkleProof(proof *MerkleProof, agentID string) (*schema.Event, error) {
	var action string
	var outcome schema.Outcome
	var severity int

	if proof.Verified {
		action = "vl.proof.verified"
		outcome = schema.OutcomeSuccess
		severity = 2
	} else {
		action = "vl.proof.failed"
		outcome = schema.OutcomeFailure
		severity = 8
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     proof.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "value-ledger",
			Host:       n.config.SourceHost,
			InstanceID: proof.EntryID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   agentID,
		},

		Action:   action,
		Target:   fmt.Sprintf("entry:%s", proof.EntryID),
		Outcome:  outcome,
		Severity: severity,

		Metadata: map[string]any{
			"vl_entry_id":   proof.EntryID,
			"vl_merkle_root": proof.Root,
			"vl_verified":   proof.Verified,
			"vl_path_length": len(proof.Path),
		},
	}

	return event, nil
}

// mapEntryTypeToAction maps entry types to canonical actions.
func (n *Normalizer) mapEntryTypeToAction(entryType string) string {
	switch entryType {
	case "work":
		return "vl.entry.work"
	case "idea":
		return "vl.entry.idea"
	case "synthesis":
		return "vl.entry.synthesis"
	case "failure":
		return "vl.entry.failure"
	case "export":
		return "vl.entry.export"
	case "revoke":
		return "vl.entry.revoked"
	default:
		return fmt.Sprintf("vl.entry.%s", entryType)
	}
}

// calculateSeverity determines severity based on entry characteristics.
func (n *Normalizer) calculateSeverity(entry *LedgerEntry) int {
	if entry.Revoked {
		return 5 // Revoked entries are notable
	}

	// High-value entries are more significant
	if entry.TotalValue > 100 {
		return 4
	}
	if entry.TotalValue > 50 {
		return 3
	}

	// Export operations are security-relevant
	if entry.EntryType == "export" {
		return 4
	}

	return 2
}

// determineOutcome determines the outcome based on entry state.
func (n *Normalizer) determineOutcome(entry *LedgerEntry) schema.Outcome {
	if entry.Revoked {
		return schema.OutcomeFailure
	}
	return schema.OutcomeSuccess
}

// mapSecuritySeverity maps Value Ledger severity to canonical severity.
func (n *Normalizer) mapSecuritySeverity(severity string) int {
	switch severity {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	case "info":
		return 2
	default:
		return 4
	}
}
