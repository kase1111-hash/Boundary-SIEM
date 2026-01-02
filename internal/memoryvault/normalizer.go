package memoryvault

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

// Normalizer converts Memory Vault events to canonical schema.
type Normalizer struct {
	config NormalizerConfig
}

// NewNormalizer creates a new normalizer with the given configuration.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	return &Normalizer{config: cfg}
}

// NormalizeAccessEvent converts an AccessEvent to a canonical schema Event.
func (n *Normalizer) NormalizeAccessEvent(access *AccessEvent) (*schema.Event, error) {
	action := fmt.Sprintf("mv.memory.%s", access.AccessType)
	severity := n.calculateAccessSeverity(access)

	var outcome schema.Outcome
	if access.Authorized {
		outcome = schema.OutcomeSuccess
	} else {
		outcome = schema.OutcomeFailure
		severity += 2 // Increase severity for denied access
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     access.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "memory-vault",
			Host:       n.config.SourceHost,
			InstanceID: access.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type:      schema.ActorService,
			ID:        access.ProfileID,
			IPAddress: access.SourceIP,
		},

		Action:   action,
		Target:   fmt.Sprintf("memory:%s", access.MemoryID),
		Outcome:  outcome,
		Severity: severity,

		Metadata: map[string]any{
			"mv_event_id":       access.ID,
			"mv_memory_id":      access.MemoryID,
			"mv_profile_id":     access.ProfileID,
			"mv_access_type":    access.AccessType,
			"mv_classification": access.Classification,
			"mv_authorized":     access.Authorized,
		},
	}

	if access.DenialReason != "" {
		event.Metadata["mv_denial_reason"] = access.DenialReason
	}

	return event, nil
}

// NormalizeIntegrityEvent converts an IntegrityEvent to a canonical schema Event.
func (n *Normalizer) NormalizeIntegrityEvent(integrity *IntegrityEvent) (*schema.Event, error) {
	action := fmt.Sprintf("mv.integrity.%s", integrity.CheckType)

	var outcome schema.Outcome
	var severity int
	if integrity.Passed {
		outcome = schema.OutcomeSuccess
		severity = 2
	} else {
		outcome = schema.OutcomeFailure
		severity = 9 // Integrity failures are critical
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     integrity.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "memory-vault",
			Host:       n.config.SourceHost,
			InstanceID: integrity.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorSystem,
			ID:   "integrity-checker",
		},

		Action:   action,
		Target:   fmt.Sprintf("profile:%s", integrity.ProfileID),
		Outcome:  outcome,
		Severity: severity,

		Metadata: map[string]any{
			"mv_event_id":      integrity.ID,
			"mv_profile_id":    integrity.ProfileID,
			"mv_check_type":    integrity.CheckType,
			"mv_passed":        integrity.Passed,
			"mv_failure_count": integrity.FailureCount,
			"mv_details":       integrity.Details,
		},
	}

	return event, nil
}

// NormalizeLockdownEvent converts a LockdownEvent to a canonical schema Event.
func (n *Normalizer) NormalizeLockdownEvent(lockdown *LockdownEvent) (*schema.Event, error) {
	var action string
	if lockdown.Active {
		action = "mv.lockdown.activated"
	} else {
		action = "mv.lockdown.deactivated"
	}

	severity := 8
	if lockdown.TriggerType == "breach_detection" {
		severity = 10
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     lockdown.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "memory-vault",
			Host:       n.config.SourceHost,
			InstanceID: lockdown.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   lockdown.InitiatedBy,
			Name: lockdown.InitiatedBy,
		},

		Action:   action,
		Target:   fmt.Sprintf("profile:%s", lockdown.ProfileID),
		Outcome:  schema.OutcomeSuccess,
		Severity: severity,

		Metadata: map[string]any{
			"mv_event_id":     lockdown.ID,
			"mv_profile_id":   lockdown.ProfileID,
			"mv_trigger_type": lockdown.TriggerType,
			"mv_active":       lockdown.Active,
			"mv_reason":       lockdown.Reason,
			"mv_initiated_by": lockdown.InitiatedBy,
		},
	}

	return event, nil
}

// NormalizeSuccessionEvent converts a SuccessionEvent to a canonical schema Event.
func (n *Normalizer) NormalizeSuccessionEvent(succession *SuccessionEvent) (*schema.Event, error) {
	action := fmt.Sprintf("mv.succession.%s", succession.EventType)

	var outcome schema.Outcome
	if succession.Authorized {
		outcome = schema.OutcomeSuccess
	} else {
		outcome = schema.OutcomeFailure
	}

	severity := 7 // Succession events are always significant

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     succession.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "memory-vault",
			Host:       n.config.SourceHost,
			InstanceID: succession.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   succession.HeirID,
			Name: fmt.Sprintf("heir-%s", succession.HeirID),
		},

		Action:   action,
		Target:   fmt.Sprintf("profile:%s", succession.ProfileID),
		Outcome:  outcome,
		Severity: severity,

		Metadata: map[string]any{
			"mv_event_id":   succession.ID,
			"mv_profile_id": succession.ProfileID,
			"mv_heir_id":    succession.HeirID,
			"mv_event_type": succession.EventType,
			"mv_authorized": succession.Authorized,
		},
	}

	if succession.Reason != "" {
		event.Metadata["mv_reason"] = succession.Reason
	}

	return event, nil
}

// NormalizeBackupEvent converts a BackupEvent to a canonical schema Event.
func (n *Normalizer) NormalizeBackupEvent(backup *BackupEvent) (*schema.Event, error) {
	action := fmt.Sprintf("mv.backup.%s", backup.EventType)

	var outcome schema.Outcome
	if backup.Success {
		outcome = schema.OutcomeSuccess
	} else {
		outcome = schema.OutcomeFailure
	}

	severity := 4
	if !backup.Success {
		severity = 6
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     backup.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "memory-vault",
			Host:       n.config.SourceHost,
			InstanceID: backup.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorSystem,
			ID:   "backup-service",
		},

		Action:   action,
		Target:   fmt.Sprintf("profile:%s", backup.ProfileID),
		Outcome:  outcome,
		Severity: severity,

		Metadata: map[string]any{
			"mv_event_id":     backup.ID,
			"mv_profile_id":   backup.ProfileID,
			"mv_backup_id":    backup.BackupID,
			"mv_event_type":   backup.EventType,
			"mv_success":      backup.Success,
			"mv_memory_count": backup.MemoryCount,
			"mv_size_bytes":   backup.SizeBytes,
		},
	}

	return event, nil
}

// NormalizePhysicalTokenEvent converts a PhysicalTokenEvent to a canonical schema Event.
func (n *Normalizer) NormalizePhysicalTokenEvent(token *PhysicalTokenEvent) (*schema.Event, error) {
	action := fmt.Sprintf("mv.token.%s", token.EventType)

	var outcome schema.Outcome
	if token.Success {
		outcome = schema.OutcomeSuccess
	} else {
		outcome = schema.OutcomeFailure
	}

	severity := 4
	if token.EventType == "failed" {
		severity = 6
	}
	if token.EventType == "revoked" {
		severity = 5
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     token.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    "memory-vault",
			Host:       n.config.SourceHost,
			InstanceID: token.ID,
			Version:    n.config.SourceVersion,
		},

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   token.ProfileID,
		},

		Action:   action,
		Target:   fmt.Sprintf("token:%s", token.TokenID),
		Outcome:  outcome,
		Severity: severity,

		Metadata: map[string]any{
			"mv_event_id":   token.ID,
			"mv_profile_id": token.ProfileID,
			"mv_token_type": token.TokenType,
			"mv_token_id":   token.TokenID,
			"mv_event_type": token.EventType,
			"mv_success":    token.Success,
		},
	}

	return event, nil
}

// calculateAccessSeverity determines severity based on access characteristics.
func (n *Normalizer) calculateAccessSeverity(access *AccessEvent) int {
	// Higher classification = higher severity
	baseSeverity := 2 + access.Classification

	// Delete operations are more significant
	if access.AccessType == "delete" {
		baseSeverity += 1
	}

	// Cap at 10
	if baseSeverity > 10 {
		baseSeverity = 10
	}

	return baseSeverity
}
