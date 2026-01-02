package learningcontracts

import (
	"boundary-siem/internal/correlation"
)

// GetDetectionRules returns all Learning Contracts detection rules.
func GetDetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// LC-001: Contract Violation Detected
		{
			ID:          "LC-001",
			Name:        "Learning Contract Violation",
			Description: "Detects violations of learning contracts which may indicate unauthorized data access",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "prefix",
				Value:    "lc.violation.",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
				{Type: "incident", Config: map[string]any{"auto_create": true}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1557"},
				"category":     "consent_violation",
			},
		},

		// LC-002: Critical Violation
		{
			ID:          "LC-002",
			Name:        "Critical Contract Violation",
			Description: "Detects critical severity violations requiring immediate attention",
			Severity:    10,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.lc_severity",
				Operator: "eq",
				Value:    "critical",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook", "email"}}},
				{Type: "incident", Config: map[string]any{"auto_create": true, "priority": "critical"}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1557", "T1119"},
				"category":     "critical_violation",
			},
		},

		// LC-003: Enforcement Gate Denial
		{
			ID:          "LC-003",
			Name:        "Enforcement Gate Denial",
			Description: "Detects denied enforcement gate checks which may indicate unauthorized operations",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.lc_allowed",
				Operator: "eq",
				Value:    false,
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "access_control",
			},
		},

		// LC-004: Mass Enforcement Denials
		{
			ID:          "LC-004",
			Name:        "Mass Enforcement Denials",
			Description: "Detects multiple denied enforcement checks indicating potential abuse",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.lc_allowed",
				Operator: "eq",
				Value:    false,
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 10,
				Window:    "5m",
				GroupBy:   []string{"metadata.lc_agent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1110"},
				"category":     "abuse_detection",
			},
		},

		// LC-005: Contract Revocation
		{
			ID:          "LC-005",
			Name:        "Learning Contract Revoked",
			Description: "Detects revocation of learning contracts",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "lc.contract.revoked",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "contract_management",
			},
		},

		// LC-006: Strategic Contract Created
		{
			ID:          "LC-006",
			Name:        "Strategic Learning Contract Created",
			Description: "Detects creation of high-trust strategic learning contracts",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.lc_contract_type",
				Operator: "eq",
				Value:    "strategic",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "high_trust_operations",
			},
		},

		// LC-007: Prohibited Domain Access
		{
			ID:          "LC-007",
			Name:        "Prohibited Domain Access Attempt",
			Description: "Detects attempts to access prohibited learning domains",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.lc_violation_type",
				Operator: "eq",
				Value:    "prohibited_domain",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1059"},
				"category":     "policy_violation",
			},
		},

		// LC-008: Export Gate Triggered
		{
			ID:          "LC-008",
			Name:        "Data Export Gate Triggered",
			Description: "Detects data export operations which require enhanced monitoring",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.lc_gate_type",
				Operator: "eq",
				Value:    "export",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1567"},
				"category":     "data_export",
			},
		},

		// LC-009: Abstraction Without Contract
		{
			ID:          "LC-009",
			Name:        "Abstraction Without Valid Contract",
			Description: "Detects abstraction operations without a valid learning contract",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "metadata.lc_gate_type", Operator: "eq", Value: "abstraction"},
					{Field: "metadata.lc_allowed", Operator: "eq", Value: false},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"category": "unauthorized_learning",
			},
		},

		// LC-010: Rapid Contract Changes
		{
			ID:          "LC-010",
			Name:        "Rapid Contract State Changes",
			Description: "Detects rapid contract state changes which may indicate manipulation",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "prefix",
				Value:    "lc.state.",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 5,
				Window:    "10m",
				GroupBy:   []string{"metadata.lc_contract_id"},
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
