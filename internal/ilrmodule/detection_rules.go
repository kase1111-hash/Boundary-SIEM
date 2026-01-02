package ilrmodule

import (
	"boundary-siem/internal/correlation"
)

// GetDetectionRules returns all ILR-Module detection rules.
func GetDetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// ILR-001: Critical Dispute Filed
		{
			ID:          "ILR-001",
			Name:        "Critical Dispute Filed",
			Description: "Detects filing of critical severity IP disputes requiring immediate attention",
			Severity:    9,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.ilr_severity",
				Operator: "eq",
				Value:    "critical",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook", "email"}}},
				{Type: "incident", Config: map[string]any{"auto_create": true}},
			},
			Metadata: map[string]any{
				"category": "dispute_monitoring",
			},
		},

		// ILR-002: Dispute Escalation Storm
		{
			ID:          "ILR-002",
			Name:        "Dispute Escalation Storm",
			Description: "Detects rapid dispute filing which may indicate coordinated attack",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "ilr.dispute.filed",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 20,
				Window:    "10m",
				GroupBy:   []string{"actor.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1499"},
				"category":     "abuse_detection",
			},
		},

		// ILR-003: Compliance Failure
		{
			ID:          "ILR-003",
			Name:        "Compliance Check Failure",
			Description: "Detects failed compliance checks which may indicate policy violations",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.ilr_passed",
				Operator: "eq",
				Value:    false,
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"category": "compliance",
			},
		},

		// ILR-004: L3 Batch Challenge
		{
			ID:          "ILR-004",
			Name:        "L3 Batch Challenged",
			Description: "Detects fraud proof challenges to L3 batch which may indicate rollup attack",
			Severity:    9,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "ilr.l3.challenged",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook", "email"}}},
				{Type: "incident", Config: map[string]any{"auto_create": true}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1565"},
				"category":     "rollup_security",
			},
		},

		// ILR-005: Oracle Dispute
		{
			ID:          "ILR-005",
			Name:        "Oracle Response Disputed",
			Description: "Detects disputed oracle responses which may indicate oracle manipulation",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.ilr_oracle_status",
				Operator: "eq",
				Value:    "disputed",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1565.001"},
				"category":     "oracle_security",
			},
		},

		// ILR-006: Low Confidence Proposal
		{
			ID:          "ILR-006",
			Name:        "Low Confidence Settlement Proposal",
			Description: "Detects LLM proposals with low confidence which may indicate difficult cases",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.ilr_confidence",
				Operator: "lt",
				Value:    float64(0.5),
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "proposal_monitoring",
			},
		},

		// ILR-007: Proposal Rejection Spike
		{
			ID:          "ILR-007",
			Name:        "Proposal Rejection Spike",
			Description: "Detects multiple rejected proposals which may indicate adversarial parties",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "ilr.proposal.rejected",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 5,
				Window:    "1h",
				GroupBy:   []string{"metadata.ilr_dispute_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "negotiation_monitoring",
			},
		},

		// ILR-008: High Stake Dispute
		{
			ID:          "ILR-008",
			Name:        "High Stake Dispute",
			Description: "Detects disputes with high stake amounts requiring enhanced monitoring",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.ilr_stake_amount",
				Operator: "gte",
				Value:    float64(100000),
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"category": "financial_monitoring",
			},
		},

		// ILR-009: Repeated Claimant Activity
		{
			ID:          "ILR-009",
			Name:        "Serial Dispute Filer",
			Description: "Detects users filing multiple disputes which may indicate abuse",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "ilr.dispute.filed",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 10,
				Window:    "24h",
				GroupBy:   []string{"actor.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "abuse_detection",
			},
		},

		// ILR-010: Arbitration Escalation
		{
			ID:          "ILR-010",
			Name:        "Dispute Escalated to Arbitration",
			Description: "Detects disputes escalating to arbitration requiring formal proceedings",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "action",
				Operator: "eq",
				Value:    "ilr.dispute.arbitration",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"category": "dispute_monitoring",
			},
		},
	}
}
