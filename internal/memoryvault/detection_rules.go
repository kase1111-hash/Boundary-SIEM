package memoryvault

import (
	"boundary-siem/internal/correlation"
)

// GetDetectionRules returns all Memory Vault detection rules.
func GetDetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// MV-001: Integrity Check Failure
		{
			ID:          "MV-001",
			Name:        "Memory Vault Integrity Failure",
			Description: "Detects failed integrity checks indicating potential tampering",
			Severity:    10,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.mv_passed",
				Operator: "eq",
				Value:    false,
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

		// MV-002: Breach-Triggered Lockdown
		{
			ID:          "MV-002",
			Name:        "Breach-Triggered Lockdown",
			Description: "Detects lockdown activated by breach detection",
			Severity:    10,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "action", Operator: "eq", Value: "mv.lockdown.activated"},
					{Field: "metadata.mv_trigger_type", Operator: "eq", Value: "breach_detection"},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook", "email"}}},
				{Type: "incident", Config: map[string]any{"auto_create": true, "priority": "critical"}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1486"},
				"category":     "breach_response",
			},
		},

		// MV-003: High Classification Access
		{
			ID:          "MV-003",
			Name:        "High Classification Memory Access",
			Description: "Detects access to high classification (level 4-5) memories",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.mv_classification",
				Operator: "gte",
				Value:    float64(4),
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "access_monitoring",
			},
		},

		// MV-004: Unauthorized Access Attempt
		{
			ID:          "MV-004",
			Name:        "Unauthorized Memory Access",
			Description: "Detects denied memory access attempts",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.mv_authorized",
				Operator: "eq",
				Value:    false,
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1078"},
				"category":     "access_control",
			},
		},

		// MV-005: Multiple Access Denials
		{
			ID:          "MV-005",
			Name:        "Multiple Access Denials",
			Description: "Detects repeated access denials indicating potential attack",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.mv_authorized",
				Operator: "eq",
				Value:    false,
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 5,
				Window:    "5m",
				GroupBy:   []string{"metadata.mv_profile_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1110"},
				"category":     "brute_force",
			},
		},

		// MV-006: Succession Access
		{
			ID:          "MV-006",
			Name:        "Heir Succession Access",
			Description: "Detects heir accessing vault through succession mechanism",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "prefix",
				Value:    "mv.succession.",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"category": "succession_monitoring",
			},
		},

		// MV-007: Dead Man Switch Triggered
		{
			ID:          "MV-007",
			Name:        "Dead Man Switch Triggered",
			Description: "Detects lockdown triggered by dead man switch",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.mv_trigger_type",
				Operator: "eq",
				Value:    "dead_man_switch",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook", "email"}}},
			},
			Metadata: map[string]any{
				"category": "emergency_response",
			},
		},

		// MV-008: Backup Failure
		{
			ID:          "MV-008",
			Name:        "Memory Vault Backup Failure",
			Description: "Detects failed backup or restore operations",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "action", Operator: "prefix", Value: "mv.backup."},
					{Field: "metadata.mv_success", Operator: "eq", Value: false},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "backup_monitoring",
			},
		},

		// MV-009: Token Verification Failure
		{
			ID:          "MV-009",
			Name:        "Physical Token Verification Failure",
			Description: "Detects failed physical token verification",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "mv.token.failed",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1078.004"},
				"category":     "authentication",
			},
		},

		// MV-010: Mass Memory Delete
		{
			ID:          "MV-010",
			Name:        "Mass Memory Deletion",
			Description: "Detects multiple memory deletions indicating potential data destruction",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.mv_access_type",
				Operator: "eq",
				Value:    "delete",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 10,
				Window:    "5m",
				GroupBy:   []string{"metadata.mv_profile_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1485"},
				"category":     "data_destruction",
			},
		},
	}
}
