package mediatornode

import (
	"boundary-siem/internal/correlation"
)

// GetDetectionRules returns all Mediator Node detection rules.
func GetDetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// MN-001: Prohibited Intent Flagged
		{
			ID:          "MN-001",
			Name:        "Prohibited Intent Detected",
			Description: "Detects intents flagged as prohibited content",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.mn_flag_type",
				Operator: "eq",
				Value:    "prohibited",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1059"},
				"category":     "content_moderation",
			},
		},

		// MN-002: Coercive Intent Flagged
		{
			ID:          "MN-002",
			Name:        "Coercive Intent Detected",
			Description: "Detects intents flagged as coercive which may indicate manipulation",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.mn_flag_type",
				Operator: "eq",
				Value:    "coercive",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"category": "content_moderation",
			},
		},

		// MN-003: Settlement Challenged
		{
			ID:          "MN-003",
			Name:        "Settlement Challenged",
			Description: "Detects challenged settlements which may indicate disputes",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "mn.settlement.challenged",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"category": "settlement_monitoring",
			},
		},

		// MN-004: Low Confidence Alignment
		{
			ID:          "MN-004",
			Name:        "Low Confidence Alignment",
			Description: "Detects alignments with low confidence scores",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.mn_confidence",
				Operator: "lt",
				Value:    float64(0.5),
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "quality_monitoring",
			},
		},

		// MN-005: Negotiation Failure Spike
		{
			ID:          "MN-005",
			Name:        "Negotiation Failure Spike",
			Description: "Detects multiple failed negotiations indicating potential issues",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "mn.negotiation.failed",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 5,
				Window:    "30m",
				GroupBy:   []string{"metadata.mn_mediator_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"category": "performance_monitoring",
			},
		},

		// MN-006: Reputation Drop
		{
			ID:          "MN-006",
			Name:        "Significant Reputation Drop",
			Description: "Detects significant decreases in mediator reputation",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "metadata.mn_change_type", Operator: "eq", Value: "decrease"},
					{Field: "metadata.mn_change_amount", Operator: "gte", Value: float64(10)},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "reputation_monitoring",
			},
		},

		// MN-007: Spam Intent Storm
		{
			ID:          "MN-007",
			Name:        "Spam Intent Storm",
			Description: "Detects multiple spam-flagged intents indicating potential attack",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.mn_flag_type",
				Operator: "eq",
				Value:    "spam",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 10,
				Window:    "5m",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1499"},
				"category":     "abuse_detection",
			},
		},

		// MN-008: Negotiation Timeout
		{
			ID:          "MN-008",
			Name:        "Negotiation Timeout",
			Description: "Detects timed-out negotiations",
			Severity:    4,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "mn.negotiation.timeout",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "negotiation_monitoring",
			},
		},

		// MN-009: Intent Archived After Flags
		{
			ID:          "MN-009",
			Name:        "Intent Archived After Multiple Flags",
			Description: "Detects intents archived due to multiple flags",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.mn_action",
				Operator: "eq",
				Value:    "archived",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "content_moderation",
			},
		},

		// MN-010: High-Volume Mediator Activity
		{
			ID:          "MN-010",
			Name:        "High-Volume Mediator Activity",
			Description: "Detects unusually high mediator activity which may indicate automation",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "prefix",
				Value:    "mn.alignment.",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 100,
				Window:    "10m",
				GroupBy:   []string{"metadata.mn_mediator_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "anomaly_detection",
			},
		},
	}
}
