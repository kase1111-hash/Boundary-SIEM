package intentlog

import (
	"boundary-siem/internal/core/schema"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Normalizer converts IntentLog events to canonical SIEM events.
type Normalizer struct{}

// NewNormalizer creates a new IntentLog normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// NormalizeProseCommit converts a prose commit to a canonical event.
func (n *Normalizer) NormalizeProseCommit(commit ProseCommit) schema.CanonicalEvent {
	severity := 3
	// Higher classification = higher severity for visibility
	switch commit.Classification {
	case "SECRET":
		severity = 5
	case "TOP_SECRET":
		severity = 6
	case "CONFIDENTIAL":
		severity = 4
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: commit.Timestamp,
		Actor:     commit.Author,
		Action:    "il.commit.created",
		Target:    commit.RepoID,
		Outcome:   "success",
		Severity:  severity,
		Metadata: map[string]any{
			"il_commit_id":      commit.ID,
			"il_repo_id":        commit.RepoID,
			"il_author":         commit.Author,
			"il_intent":         commit.Intent,
			"il_semantic_hash":  commit.SemanticHash,
			"il_previous_hash":  commit.PreviousHash,
			"il_classification": commit.Classification,
			"il_branch":         commit.Branch,
			"source":            "intentlog",
		},
		Source:    "intentlog",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeSemanticDiff converts a semantic diff to a canonical event.
func (n *Normalizer) NormalizeSemanticDiff(diff SemanticDiff) schema.CanonicalEvent {
	severity := 3
	if diff.ChangeType == "contradiction" {
		severity = 6
	} else if diff.ChangeType == "retraction" {
		severity = 5
	}
	if diff.Significance >= 0.8 {
		severity = max(severity, 5)
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: diff.GeneratedAt,
		Actor:     "intentlog",
		Action:    fmt.Sprintf("il.diff.%s", diff.ChangeType),
		Target:    diff.RepoID,
		Outcome:   "success",
		Severity:  severity,
		Metadata: map[string]any{
			"il_diff_id":      diff.ID,
			"il_repo_id":      diff.RepoID,
			"il_from_commit":  diff.FromCommit,
			"il_to_commit":    diff.ToCommit,
			"il_summary":      diff.Summary,
			"il_change_type":  diff.ChangeType,
			"il_significance": diff.Significance,
			"source":          "intentlog",
		},
		Source:    "intentlog",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeBranchEvent converts a branch event to a canonical event.
func (n *Normalizer) NormalizeBranchEvent(event BranchEvent) schema.CanonicalEvent {
	outcome := "success"
	if !event.Success {
		outcome = "failure"
	}

	severity := 3
	if !event.Success {
		severity = 5
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.Author,
		Action:    fmt.Sprintf("il.branch.%s", event.EventType),
		Target:    event.BranchName,
		Outcome:   outcome,
		Severity:  severity,
		Metadata: map[string]any{
			"il_event_id":    event.ID,
			"il_repo_id":     event.RepoID,
			"il_event_type":  event.EventType,
			"il_branch_name": event.BranchName,
			"il_from_branch": event.FromBranch,
			"il_author":      event.Author,
			"il_success":     event.Success,
			"source":         "intentlog",
		},
		Source:    "intentlog",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeChainEvent converts a chain integrity event to a canonical event.
func (n *Normalizer) NormalizeChainEvent(event ChainEvent) schema.CanonicalEvent {
	outcome := "success"
	if !event.Passed {
		outcome = "failure"
	}

	severity := 3
	if !event.Passed {
		severity = 10 // Critical - chain integrity failure
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     "intentlog",
		Action:    fmt.Sprintf("il.chain.%s", event.EventType),
		Target:    event.RepoID,
		Outcome:   outcome,
		Severity:  severity,
		Metadata: map[string]any{
			"il_event_id":      event.ID,
			"il_repo_id":       event.RepoID,
			"il_event_type":    event.EventType,
			"il_passed":        event.Passed,
			"il_failure_point": event.FailurePoint,
			"il_details":       event.Details,
			"source":           "intentlog",
		},
		Source:    "intentlog",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeExportEvent converts an export event to a canonical event.
func (n *Normalizer) NormalizeExportEvent(event ExportEvent) schema.CanonicalEvent {
	outcome := "success"
	if !event.Success {
		outcome = "failure"
	}

	severity := 4 // Exports are security-relevant

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.Requester,
		Action:    fmt.Sprintf("il.export.%s", event.ExportType),
		Target:    event.RepoID,
		Outcome:   outcome,
		Severity:  severity,
		Metadata: map[string]any{
			"il_event_id":     event.ID,
			"il_repo_id":      event.RepoID,
			"il_export_type":  event.ExportType,
			"il_format":       event.Format,
			"il_commit_range": event.CommitRange,
			"il_requester":    event.Requester,
			"il_success":      event.Success,
			"source":          "intentlog",
		},
		Source:    "intentlog",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeObservationEvent converts an observation event to a canonical event.
func (n *Normalizer) NormalizeObservationEvent(event ObservationEvent) schema.CanonicalEvent {
	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.ObserverID,
		Action:    fmt.Sprintf("il.observation.%s", event.EventType),
		Target:    event.SessionID,
		Outcome:   "success",
		Severity:  2,
		Metadata: map[string]any{
			"il_event_id":    event.ID,
			"il_repo_id":     event.RepoID,
			"il_observer_id": event.ObserverID,
			"il_session_id":  event.SessionID,
			"il_event_type":  event.EventType,
			"il_duration_ms": event.Duration.Milliseconds(),
			"source":         "intentlog",
		},
		Source:    "intentlog",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeKeyEvent converts a key management event to a canonical event.
func (n *Normalizer) NormalizeKeyEvent(event KeyEvent) schema.CanonicalEvent {
	outcome := "success"
	if !event.Success {
		outcome = "failure"
	}

	severity := 5 // Key operations are security-sensitive
	if event.EventType == "revoked" {
		severity = 6
	}
	if !event.Success {
		severity = 7
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     "intentlog",
		Action:    fmt.Sprintf("il.key.%s", event.EventType),
		Target:    event.KeyID,
		Outcome:   outcome,
		Severity:  severity,
		Metadata: map[string]any{
			"il_event_id":   event.ID,
			"il_repo_id":    event.RepoID,
			"il_event_type": event.EventType,
			"il_key_id":     event.KeyID,
			"il_algorithm":  event.Algorithm,
			"il_success":    event.Success,
			"source":        "intentlog",
		},
		Source:    "intentlog",
		CreatedAt: time.Now().UTC(),
	}
}
