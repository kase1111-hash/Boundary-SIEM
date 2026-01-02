package valueledger

import (
	"boundary-siem/internal/correlation"
)

// GetDetectionRules returns all Value Ledger detection rules.
func GetDetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// VL-001: High-Value Entry Export
		{
			ID:          "VL-001",
			Name:        "High-Value Entry Export",
			Description: "Detects export of high-value ledger entries which may indicate data exfiltration",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "vl.entry.export",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1567", "T1020"},
				"category":     "data_exfiltration",
			},
		},

		// VL-002: Mass Entry Revocation
		{
			ID:          "VL-002",
			Name:        "Mass Entry Revocation",
			Description: "Detects multiple entry revocations in a short period indicating potential data integrity attack",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "vl.entry.revoked",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 10,
				Window:    "5m",
				GroupBy:   []string{"actor.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1485", "T1565"},
				"category":     "data_destruction",
			},
		},

		// VL-003: Merkle Proof Verification Failure
		{
			ID:          "VL-003",
			Name:        "Merkle Proof Verification Failure",
			Description: "Detects failed Merkle proof verification indicating potential ledger tampering",
			Severity:    9,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "vl.proof.failed",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook", "email"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1565.001"},
				"category":     "integrity_violation",
			},
		},

		// VL-004: Unauthorized Agent Activity
		{
			ID:          "VL-004",
			Name:        "Unauthorized Agent Activity",
			Description: "Detects security events indicating unauthorized agent access",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "prefix",
				Value:    "vl.security.",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1078"},
				"category":     "unauthorized_access",
			},
		},

		// VL-005: Anomalous Value Spike
		{
			ID:          "VL-005",
			Name:        "Anomalous Value Spike",
			Description: "Detects entries with unusually high value scores which may indicate manipulation",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.vl_total_value",
				Operator: "gte",
				Value:    float64(500),
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "anomaly_detection",
			},
		},

		// VL-006: Chain Integrity Alert
		{
			ID:          "VL-006",
			Name:        "Chain Integrity Alert",
			Description: "Detects chain integrity verification failures",
			Severity:    10,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "vl.security.chain_integrity_failure",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook", "email"}}},
				{Type: "incident", Config: map[string]any{"auto_create": true}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1565.001"},
				"category":     "critical_integrity",
			},
		},

		// VL-007: Rapid Entry Creation
		{
			ID:          "VL-007",
			Name:        "Rapid Entry Creation",
			Description: "Detects unusually rapid entry creation which may indicate automated abuse",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "prefix",
				Value:    "vl.entry.",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 50,
				Window:    "1m",
				GroupBy:   []string{"actor.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "abuse_detection",
			},
		},

		// VL-008: Synthesis Without Prior Work
		{
			ID:          "VL-008",
			Name:        "Synthesis Without Prior Work",
			Description: "Detects synthesis entries from agents with no prior work entries",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "vl.entry.synthesis",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:    "absence",
				Window:  "24h",
				GroupBy: []string{"actor.id"},
				AbsenceCondition: &correlation.Condition{
					Field:    "action",
					Operator: "eq",
					Value:    "vl.entry.work",
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "policy_violation",
			},
		},
	}
}
