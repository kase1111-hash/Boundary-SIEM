package synthmind

import (
	"boundary-siem/internal/correlation"
)

// GetDetectionRules returns all Synth Mind detection rules.
func GetDetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// SM-001: Emotional Anomaly Detected
		{
			ID:          "SM-001",
			Name:        "Emotional State Anomaly",
			Description: "Detects anomalous emotional states in the AI agent",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.sm_anomaly",
				Operator: "eq",
				Value:    true,
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"category": "agent_monitoring",
			},
		},

		// SM-002: Safety Guardrail Triggered
		{
			ID:          "SM-002",
			Name:        "Safety Guardrail Triggered",
			Description: "Detects when safety guardrails are activated",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.sm_triggered",
				Operator: "eq",
				Value:    true,
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"category": "safety_monitoring",
			},
		},

		// SM-003: Extended Negative Valence
		{
			ID:          "SM-003",
			Name:        "Extended Negative Emotional State",
			Description: "Detects prolonged negative emotional valence",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.sm_valence",
				Operator: "lt",
				Value:    float64(-0.5),
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 5,
				Window:    "30m",
				GroupBy:   []string{"metadata.sm_agent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "wellbeing_monitoring",
			},
		},

		// SM-004: Reflection Module Failure
		{
			ID:          "SM-004",
			Name:        "Meta-Reflection Failure",
			Description: "Detects failures in the meta-reflection module",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "metadata.sm_module", Operator: "eq", Value: "reflection"},
					{Field: "metadata.sm_success", Operator: "eq", Value: false},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "module_monitoring",
			},
		},

		// SM-005: High Uncertainty State
		{
			ID:          "SM-005",
			Name:        "High Uncertainty State",
			Description: "Detects when agent is in high uncertainty state",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.sm_uncertainty",
				Operator: "gte",
				Value:    float64(0.8),
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "agent_monitoring",
			},
		},

		// SM-006: Tool Usage Failure
		{
			ID:          "SM-006",
			Name:        "Tool Usage Failure",
			Description: "Detects failed tool usage in sandboxed environment",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "action", Operator: "prefix", Value: "sm.tool."},
					{Field: "outcome", Operator: "eq", Value: "failure"},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "tool_monitoring",
			},
		},

		// SM-007: Peer Communication Failure
		{
			ID:          "SM-007",
			Name:        "Peer Communication Failure",
			Description: "Detects failed peer-to-peer agent communication",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "action", Operator: "prefix", Value: "sm.social."},
					{Field: "outcome", Operator: "eq", Value: "failure"},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "social_monitoring",
			},
		},

		// SM-008: Dreaming Prediction Mismatch
		{
			ID:          "SM-008",
			Name:        "Large Prediction Mismatch",
			Description: "Detects significant mismatch between predicted and actual outcomes",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.sm_validation_gap",
				Operator: "gte",
				Value:    float64(0.7),
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "prediction_monitoring",
			},
		},

		// SM-009: Multiple Safety Triggers
		{
			ID:          "SM-009",
			Name:        "Multiple Safety Triggers",
			Description: "Detects multiple safety guardrail activations indicating potential issues",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.sm_triggered",
				Operator: "eq",
				Value:    true,
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 3,
				Window:    "10m",
				GroupBy:   []string{"metadata.sm_agent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"category": "safety_monitoring",
			},
		},

		// SM-010: Significant Behavioral Change
		{
			ID:          "SM-010",
			Name:        "Significant Behavioral Change Detected",
			Description: "Detects significant behavioral insights from reflection module",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.sm_severity",
				Operator: "eq",
				Value:    "significant",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "behavior_monitoring",
			},
		},
	}
}
