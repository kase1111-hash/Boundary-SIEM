package natlangchain

import (
	"testing"
	"time"

	"boundary-siem/internal/schema"
)

func TestNormalizer_NormalizeEntry(t *testing.T) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())

	tests := []struct {
		name         string
		entry        *Entry
		eventType    string
		wantAction   string
		wantSeverity int
		wantOutcome  schema.Outcome
	}{
		{
			name: "validated entry",
			entry: &Entry{
				ID:          "entry-123",
				ChainID:     "main",
				BlockNumber: 100,
				BlockHash:   "abc123",
				Timestamp:   time.Now(),
				Author:      "alice",
				AuthorID:    "user-1",
				Content:     "This is a test entry",
				ContentHash: "hash123",
				EntryType:   "prose",
				Validated:   true,
				ValidatorID: "validator-1",
			},
			eventType:    "entry.validated",
			wantAction:   "nlc.entry.validated",
			wantSeverity: 2,
			wantOutcome:  schema.OutcomeSuccess,
		},
		{
			name: "rejected entry",
			entry: &Entry{
				ID:          "entry-456",
				ChainID:     "main",
				BlockNumber: 101,
				Timestamp:   time.Now(),
				Author:      "bob",
				AuthorID:    "user-2",
				Content:     "Rejected content",
				Validated:   false,
			},
			eventType:    "entry.rejected",
			wantAction:   "nlc.entry.rejected",
			wantSeverity: 6,
			wantOutcome:  schema.OutcomeFailure,
		},
		{
			name: "created entry (pending validation)",
			entry: &Entry{
				ID:          "entry-789",
				ChainID:     "main",
				BlockNumber: 102,
				Timestamp:   time.Now(),
				Author:      "charlie",
				AuthorID:    "user-3",
				Content:     "New entry awaiting validation",
				Validated:   false,
			},
			eventType:    "entry.created",
			wantAction:   "nlc.entry.created",
			wantSeverity: 3,
			wantOutcome:  schema.OutcomeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := normalizer.NormalizeEntry(tt.entry, tt.eventType)
			if err != nil {
				t.Fatalf("NormalizeEntry() error = %v", err)
			}

			if event.Action != tt.wantAction {
				t.Errorf("Action = %v, want %v", event.Action, tt.wantAction)
			}
			if event.Severity != tt.wantSeverity {
				t.Errorf("Severity = %v, want %v", event.Severity, tt.wantSeverity)
			}
			if event.Outcome != tt.wantOutcome {
				t.Errorf("Outcome = %v, want %v", event.Outcome, tt.wantOutcome)
			}
			if event.Source.Product != "natlangchain" {
				t.Errorf("Source.Product = %v, want natlangchain", event.Source.Product)
			}
			if event.Actor == nil {
				t.Error("Actor should not be nil")
			} else {
				if event.Actor.Name != tt.entry.Author {
					t.Errorf("Actor.Name = %v, want %v", event.Actor.Name, tt.entry.Author)
				}
			}
		})
	}
}

func TestNormalizer_NormalizeDispute(t *testing.T) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())

	now := time.Now()
	resolvedAt := now.Add(time.Hour)

	tests := []struct {
		name         string
		dispute      *Dispute
		eventType    string
		wantAction   string
		wantSeverity int
		wantOutcome  schema.Outcome
	}{
		{
			name: "open dispute",
			dispute: &Dispute{
				ID:      "dispute-1",
				EntryID: "entry-123",
				FiledBy: "alice",
				FiledAt: now,
				Reason:  "Incorrect interpretation",
				Status:  "open",
			},
			eventType:    "dispute.filed",
			wantAction:   "nlc.dispute.filed",
			wantSeverity: 5,
			wantOutcome:  schema.OutcomeUnknown,
		},
		{
			name: "escalated dispute",
			dispute: &Dispute{
				ID:      "dispute-2",
				EntryID: "entry-456",
				FiledBy: "bob",
				FiledAt: now,
				Reason:  "Serious violation",
				Status:  "escalated",
			},
			eventType:    "dispute.escalated",
			wantAction:   "nlc.dispute.escalated",
			wantSeverity: 7,
			wantOutcome:  schema.OutcomeFailure,
		},
		{
			name: "resolved dispute",
			dispute: &Dispute{
				ID:         "dispute-3",
				EntryID:    "entry-789",
				FiledBy:    "charlie",
				FiledAt:    now,
				Reason:     "Minor issue",
				Status:     "resolved",
				Resolution: "Clarification provided",
				ResolvedAt: &resolvedAt,
				ResolvedBy: "moderator-1",
			},
			eventType:    "dispute.resolved",
			wantAction:   "nlc.dispute.resolved",
			wantSeverity: 3,
			wantOutcome:  schema.OutcomeSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := normalizer.NormalizeDispute(tt.dispute, tt.eventType)
			if err != nil {
				t.Fatalf("NormalizeDispute() error = %v", err)
			}

			if event.Action != tt.wantAction {
				t.Errorf("Action = %v, want %v", event.Action, tt.wantAction)
			}
			if event.Severity != tt.wantSeverity {
				t.Errorf("Severity = %v, want %v", event.Severity, tt.wantSeverity)
			}
			if event.Outcome != tt.wantOutcome {
				t.Errorf("Outcome = %v, want %v", event.Outcome, tt.wantOutcome)
			}
		})
	}
}

func TestNormalizer_NormalizeSemanticDrift(t *testing.T) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())

	tests := []struct {
		name         string
		drift        *SemanticDrift
		wantAction   string
		wantSeverity int
	}{
		{
			name: "critical drift",
			drift: &SemanticDrift{
				ID:              "drift-1",
				EntryID:         "entry-123",
				DetectedAt:      time.Now(),
				OriginalMeaning: "Original intent",
				DriftedMeaning:  "Completely different meaning",
				DriftScore:      0.95,
				ValidatorID:     "validator-1",
				Severity:        "critical",
			},
			wantAction:   "nlc.semantic.drift.critical",
			wantSeverity: 9,
		},
		{
			name: "high drift",
			drift: &SemanticDrift{
				ID:              "drift-2",
				EntryID:         "entry-456",
				DetectedAt:      time.Now(),
				OriginalMeaning: "Original meaning",
				DriftedMeaning:  "Significantly different",
				DriftScore:      0.75,
				ValidatorID:     "validator-2",
				Severity:        "high",
			},
			wantAction:   "nlc.semantic.drift",
			wantSeverity: 7,
		},
		{
			name: "low drift",
			drift: &SemanticDrift{
				ID:              "drift-3",
				EntryID:         "entry-789",
				DetectedAt:      time.Now(),
				OriginalMeaning: "Original",
				DriftedMeaning:  "Slightly different",
				DriftScore:      0.25,
				ValidatorID:     "validator-3",
				Severity:        "low",
			},
			wantAction:   "nlc.semantic.drift",
			wantSeverity: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := normalizer.NormalizeSemanticDrift(tt.drift)
			if err != nil {
				t.Fatalf("NormalizeSemanticDrift() error = %v", err)
			}

			if event.Action != tt.wantAction {
				t.Errorf("Action = %v, want %v", event.Action, tt.wantAction)
			}
			if event.Severity != tt.wantSeverity {
				t.Errorf("Severity = %v, want %v", event.Severity, tt.wantSeverity)
			}
			if event.Outcome != schema.OutcomeFailure {
				t.Errorf("Outcome = %v, want failure", event.Outcome)
			}
		})
	}
}

func TestNormalizer_NormalizeValidationEvent(t *testing.T) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())

	tests := []struct {
		name        string
		event       *ValidationEvent
		wantAction  string
		wantOutcome schema.Outcome
	}{
		{
			name: "paraphrase validation",
			event: &ValidationEvent{
				ID:          "val-1",
				EntryID:     "entry-123",
				ValidatorID: "validator-1",
				Timestamp:   time.Now(),
				EventType:   "paraphrase",
				Outcome:     "success",
				Confidence:  0.85,
				Paraphrase:  "Restated understanding",
			},
			wantAction:  "nlc.validation.paraphrase",
			wantOutcome: schema.OutcomeSuccess,
		},
		{
			name: "debate validation",
			event: &ValidationEvent{
				ID:            "val-2",
				EntryID:       "entry-456",
				ValidatorID:   "validator-2",
				Timestamp:     time.Now(),
				EventType:     "debate",
				Outcome:       "success",
				Confidence:    0.72,
				DebateRole:    "skeptic",
				DebateMessage: "Challenge to interpretation",
			},
			wantAction:  "nlc.validation.debate",
			wantOutcome: schema.OutcomeSuccess,
		},
		{
			name: "rejection",
			event: &ValidationEvent{
				ID:          "val-3",
				EntryID:     "entry-789",
				ValidatorID: "validator-3",
				Timestamp:   time.Now(),
				EventType:   "rejection",
				Outcome:     "failure",
				Confidence:  0.95,
			},
			wantAction:  "nlc.validation.rejection",
			wantOutcome: schema.OutcomeFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := normalizer.NormalizeValidationEvent(tt.event)
			if err != nil {
				t.Fatalf("NormalizeValidationEvent() error = %v", err)
			}

			if event.Action != tt.wantAction {
				t.Errorf("Action = %v, want %v", event.Action, tt.wantAction)
			}
			if event.Outcome != tt.wantOutcome {
				t.Errorf("Outcome = %v, want %v", event.Outcome, tt.wantOutcome)
			}
		})
	}
}

func TestActionMappings(t *testing.T) {
	// Verify all expected actions are mapped
	expectedActions := []string{
		"entry.created", "entry.validated", "entry.rejected",
		"dispute.filed", "dispute.resolved", "dispute.escalated",
		"contract.created", "contract.matched", "contract.completed",
		"negotiation.started", "negotiation.completed", "negotiation.failed",
		"validation.paraphrase", "validation.debate", "validation.consensus",
		"semantic.drift.detected", "semantic.drift.critical",
		"security.adversarial", "security.manipulation",
	}

	for _, action := range expectedActions {
		if _, ok := ActionMappings[action]; !ok {
			t.Errorf("Expected action %s not found in ActionMappings", action)
		}
	}
}
