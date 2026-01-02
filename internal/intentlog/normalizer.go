package intentlog

import (
	"boundary-siem/internal/schema"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// NormalizerConfig holds configuration for the normalizer.
type NormalizerConfig struct {
	SourceProduct string `yaml:"source_product"`
	SourceHost    string `yaml:"source_host"`
	TenantID      string `yaml:"tenant_id"`
}

// DefaultNormalizerConfig returns the default normalizer configuration.
func DefaultNormalizerConfig() NormalizerConfig {
	return NormalizerConfig{
		SourceProduct: "intentlog",
		SourceHost:    "localhost",
		TenantID:      "default",
	}
}

// Normalizer converts IntentLog events to canonical SIEM events.
type Normalizer struct {
	sourceProduct   string
	sourceHost      string
	defaultTenantID string
}

// NewNormalizer creates a new IntentLog normalizer.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	product := cfg.SourceProduct
	if product == "" {
		product = "intentlog"
	}
	return &Normalizer{
		sourceProduct:   product,
		sourceHost:      cfg.SourceHost,
		defaultTenantID: cfg.TenantID,
	}
}

// NormalizeProseCommit converts a prose commit to a canonical event.
func (n *Normalizer) NormalizeProseCommit(commit *ProseCommit) (*schema.Event, error) {
	if commit == nil {
		return nil, fmt.Errorf("prose commit is nil")
	}

	severity := 3
	switch commit.Classification {
	case "SECRET":
		severity = 5
	case "TOP_SECRET":
		severity = 6
	case "CONFIDENTIAL":
		severity = 4
	}

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     commit.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: commit.ID,
		},
		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   commit.Author,
			Name: commit.Author,
		},
		Action:   "il.commit.created",
		Target:   commit.RepoID,
		Outcome:  schema.OutcomeSuccess,
		Severity: severity,
		Metadata: map[string]any{
			"il_commit_id":      commit.ID,
			"il_repo_id":        commit.RepoID,
			"il_author":         commit.Author,
			"il_intent":         commit.Intent,
			"il_semantic_hash":  commit.SemanticHash,
			"il_previous_hash":  commit.PreviousHash,
			"il_classification": commit.Classification,
			"il_branch":         commit.Branch,
		},
	}, nil
}

// NormalizeSemanticDiff converts a semantic diff to a canonical event.
func (n *Normalizer) NormalizeSemanticDiff(diff *SemanticDiff) (*schema.Event, error) {
	if diff == nil {
		return nil, fmt.Errorf("semantic diff is nil")
	}

	severity := 3
	if diff.ChangeType == "contradiction" {
		severity = 6
	} else if diff.ChangeType == "retraction" {
		severity = 5
	}
	if diff.Significance >= 0.8 {
		severity = max(severity, 5)
	}

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     diff.GeneratedAt,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: diff.ID,
		},
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   "intentlog",
			Name: "intentlog-diff-engine",
		},
		Action:   fmt.Sprintf("il.diff.%s", diff.ChangeType),
		Target:   diff.RepoID,
		Outcome:  schema.OutcomeSuccess,
		Severity: severity,
		Metadata: map[string]any{
			"il_diff_id":      diff.ID,
			"il_repo_id":      diff.RepoID,
			"il_from_commit":  diff.FromCommit,
			"il_to_commit":    diff.ToCommit,
			"il_summary":      diff.Summary,
			"il_change_type":  diff.ChangeType,
			"il_significance": diff.Significance,
		},
	}, nil
}

// NormalizeBranchEvent converts a branch event to a canonical event.
func (n *Normalizer) NormalizeBranchEvent(event *BranchEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("branch event is nil")
	}

	var outcome schema.Outcome
	if event.Success {
		outcome = schema.OutcomeSuccess
	} else {
		outcome = schema.OutcomeFailure
	}

	severity := 3
	if !event.Success {
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
		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   event.Author,
			Name: event.Author,
		},
		Action:   fmt.Sprintf("il.branch.%s", event.EventType),
		Target:   event.BranchName,
		Outcome:  outcome,
		Severity: severity,
		Metadata: map[string]any{
			"il_event_id":    event.ID,
			"il_repo_id":     event.RepoID,
			"il_event_type":  event.EventType,
			"il_branch_name": event.BranchName,
			"il_from_branch": event.FromBranch,
			"il_author":      event.Author,
			"il_success":     event.Success,
		},
	}, nil
}

// NormalizeChainEvent converts a chain integrity event to a canonical event.
func (n *Normalizer) NormalizeChainEvent(event *ChainEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("chain event is nil")
	}

	var outcome schema.Outcome
	if event.Passed {
		outcome = schema.OutcomeSuccess
	} else {
		outcome = schema.OutcomeFailure
	}

	severity := 3
	if !event.Passed {
		severity = 10 // Critical - chain integrity failure
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
		Actor: &schema.Actor{
			Type: schema.ActorSystem,
			ID:   "intentlog-chain-verifier",
		},
		Action:   fmt.Sprintf("il.chain.%s", event.EventType),
		Target:   event.RepoID,
		Outcome:  outcome,
		Severity: severity,
		Metadata: map[string]any{
			"il_event_id":      event.ID,
			"il_repo_id":       event.RepoID,
			"il_event_type":    event.EventType,
			"il_passed":        event.Passed,
			"il_failure_point": event.FailurePoint,
			"il_details":       event.Details,
		},
	}, nil
}

// NormalizeExportEvent converts an export event to a canonical event.
func (n *Normalizer) NormalizeExportEvent(event *ExportEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("export event is nil")
	}

	var outcome schema.Outcome
	if event.Success {
		outcome = schema.OutcomeSuccess
	} else {
		outcome = schema.OutcomeFailure
	}

	severity := 4 // Exports are security-relevant

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
		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   event.Requester,
			Name: event.Requester,
		},
		Action:   fmt.Sprintf("il.export.%s", event.ExportType),
		Target:   event.RepoID,
		Outcome:  outcome,
		Severity: severity,
		Metadata: map[string]any{
			"il_event_id":     event.ID,
			"il_repo_id":      event.RepoID,
			"il_export_type":  event.ExportType,
			"il_format":       event.Format,
			"il_commit_range": event.CommitRange,
			"il_requester":    event.Requester,
			"il_success":      event.Success,
		},
	}, nil
}

// NormalizeObservationEvent converts an observation event to a canonical event.
func (n *Normalizer) NormalizeObservationEvent(event *ObservationEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("observation event is nil")
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
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   event.ObserverID,
			Name: fmt.Sprintf("observer-%s", event.ObserverID),
		},
		Action:   fmt.Sprintf("il.observation.%s", event.EventType),
		Target:   event.SessionID,
		Outcome:  schema.OutcomeSuccess,
		Severity: 2,
		Metadata: map[string]any{
			"il_event_id":    event.ID,
			"il_repo_id":     event.RepoID,
			"il_observer_id": event.ObserverID,
			"il_session_id":  event.SessionID,
			"il_event_type":  event.EventType,
			"il_duration_ms": event.Duration.Milliseconds(),
		},
	}, nil
}

// NormalizeKeyEvent converts a key management event to a canonical event.
func (n *Normalizer) NormalizeKeyEvent(event *KeyEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("key event is nil")
	}

	var outcome schema.Outcome
	if event.Success {
		outcome = schema.OutcomeSuccess
	} else {
		outcome = schema.OutcomeFailure
	}

	severity := 5 // Key operations are security-sensitive
	if event.EventType == "revoked" {
		severity = 6
	}
	if !event.Success {
		severity = 7
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
		Actor: &schema.Actor{
			Type: schema.ActorSystem,
			ID:   "intentlog-key-manager",
		},
		Action:   fmt.Sprintf("il.key.%s", event.EventType),
		Target:   event.KeyID,
		Outcome:  outcome,
		Severity: severity,
		Metadata: map[string]any{
			"il_event_id":   event.ID,
			"il_repo_id":    event.RepoID,
			"il_event_type": event.EventType,
			"il_key_id":     event.KeyID,
			"il_algorithm":  event.Algorithm,
			"il_success":    event.Success,
		},
	}, nil
}
