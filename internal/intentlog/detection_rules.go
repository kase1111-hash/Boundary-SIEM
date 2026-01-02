package intentlog

import (
	"boundary-siem/internal/correlation"
)

// GetDetectionRules returns all IntentLog detection rules.
func GetDetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// IL-001: Chain Integrity Failure
		{
			ID:          "IL-001",
			Name:        "IntentLog Chain Integrity Failure",
			Description: "Detects failed chain integrity verification indicating potential tampering",
			Severity:    10,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "action", Operator: "prefix", Value: "il.chain."},
					{Field: "metadata.il_passed", Operator: "eq", Value: false},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook", "email"}}},
				{Type: "incident", Config: map[string]any{"auto_create": true, "priority": "critical"}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1565.001"},
				"category":     "integrity_violation",
			},
		},

		// IL-002: High Classification Export
		{
			ID:          "IL-002",
			Name:        "High Classification Data Export",
			Description: "Detects export of SECRET or TOP_SECRET classified content",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "action", Operator: "eq", Value: "il.export.requested"},
					{Field: "metadata.il_classification", Operator: "in", Value: []string{"SECRET", "TOP_SECRET"}},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1567"},
				"category":     "data_exfiltration",
			},
		},

		// IL-003: Semantic Contradiction
		{
			ID:          "IL-003",
			Name:        "Semantic Contradiction Detected",
			Description: "Detects commits that contradict previous reasoning",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.il_change_type",
				Operator: "eq",
				Value:    "contradiction",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "reasoning_monitoring",
			},
		},

		// IL-004: Signature Verification Failed
		{
			ID:          "IL-004",
			Name:        "Commit Signature Verification Failed",
			Description: "Detects failed signature verification on commits",
			Severity:    9,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "metadata.il_event_type", Operator: "eq", Value: "signature_check"},
					{Field: "metadata.il_passed", Operator: "eq", Value: false},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1565"},
				"category":     "signature_verification",
			},
		},

		// IL-005: Rapid Commit Activity
		{
			ID:          "IL-005",
			Name:        "Rapid Commit Activity",
			Description: "Detects unusually rapid commit activity which may indicate automation",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "il.commit.created",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 20,
				Window:    "5m",
				GroupBy:   []string{"metadata.il_author"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "anomaly_detection",
			},
		},

		// IL-006: Key Revocation
		{
			ID:          "IL-006",
			Name:        "Signing Key Revoked",
			Description: "Detects revocation of signing keys",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.il_event_type",
				Operator: "eq",
				Value:    "revoked",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "key_management",
			},
		},

		// IL-007: Branch Manipulation
		{
			ID:          "IL-007",
			Name:        "Failed Branch Operation",
			Description: "Detects failed branch operations which may indicate access issues",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "action", Operator: "prefix", Value: "il.branch."},
					{Field: "outcome", Operator: "eq", Value: "failure"},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "branch_monitoring",
			},
		},

		// IL-008: High Significance Change
		{
			ID:          "IL-008",
			Name:        "High Significance Semantic Change",
			Description: "Detects semantically significant changes requiring attention",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.il_significance",
				Operator: "gte",
				Value:    float64(0.8),
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "change_monitoring",
			},
		},

		// IL-009: Export Failure
		{
			ID:          "IL-009",
			Name:        "Data Export Failure",
			Description: "Detects failed data export operations",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "action", Operator: "prefix", Value: "il.export."},
					{Field: "outcome", Operator: "eq", Value: "failure"},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "export_monitoring",
			},
		},

		// IL-010: Retraction Pattern
		{
			ID:          "IL-010",
			Name:        "Multiple Retractions",
			Description: "Detects multiple retractions which may indicate quality issues",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.il_change_type",
				Operator: "eq",
				Value:    "retraction",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 3,
				Window:    "1h",
				GroupBy:   []string{"metadata.il_repo_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "quality_monitoring",
			},
		},
	}
}
