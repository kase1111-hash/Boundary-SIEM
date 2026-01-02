package rramodule

import (
	"boundary-siem/internal/correlation"
)

// GetDetectionRules returns all RRA-Module detection rules.
func GetDetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// RRA-001: Contract Deployment Failed
		{
			ID:          "RRA-001",
			Name:        "Smart Contract Deployment Failed",
			Description: "Detects failed smart contract deployments",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "metadata.rra_event_type", Operator: "eq", Value: "deployed"},
					{Field: "metadata.rra_success", Operator: "eq", Value: false},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"category": "contract_monitoring",
			},
		},

		// RRA-002: High Value Transaction
		{
			ID:          "RRA-002",
			Name:        "High Value Transaction",
			Description: "Detects high value contract interactions",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.rra_value",
				Operator: "gte",
				Value:    float64(10000),
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "financial_monitoring",
			},
		},

		// RRA-003: Security Event Blocked
		{
			ID:          "RRA-003",
			Name:        "Security Event Blocked",
			Description: "Detects blocked security events",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.rra_blocked",
				Operator: "eq",
				Value:    true,
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"category": "security_monitoring",
			},
		},

		// RRA-004: Suspicious Query
		{
			ID:          "RRA-004",
			Name:        "Suspicious Query Detected",
			Description: "Detects suspicious queries to repository agents",
			Severity:    8,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.rra_event_type",
				Operator: "eq",
				Value:    "suspicious_query",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1059"},
				"category":     "threat_detection",
			},
		},

		// RRA-005: Negotiation Failure Spike
		{
			ID:          "RRA-005",
			Name:        "Negotiation Failure Spike",
			Description: "Detects multiple rejected negotiations",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.rra_event_type",
				Operator: "eq",
				Value:    "rejected",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 5,
				Window:    "30m",
				GroupBy:   []string{"metadata.rra_agent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "negotiation_monitoring",
			},
		},

		// RRA-006: Repository Ingestion Failed
		{
			ID:          "RRA-006",
			Name:        "Repository Ingestion Failed",
			Description: "Detects failed repository ingestion",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "action", Operator: "prefix", Value: "rra.ingestion."},
					{Field: "metadata.rra_success", Operator: "eq", Value: false},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "ingestion_monitoring",
			},
		},

		// RRA-007: FIDO2 Challenge Failed
		{
			ID:          "RRA-007",
			Name:        "FIDO2 Authentication Failed",
			Description: "Detects failed FIDO2 hardware authentication",
			Severity:    7,
			Enabled:     true,
			Condition: correlation.Condition{
				And: []correlation.Condition{
					{Field: "metadata.rra_event_type", Operator: "eq", Value: "fido2_challenge"},
					{Field: "metadata.rra_blocked", Operator: "eq", Value: true},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1078.004"},
				"category":     "authentication",
			},
		},

		// RRA-008: Governance Proposal Executed
		{
			ID:          "RRA-008",
			Name:        "Governance Proposal Executed",
			Description: "Detects executed governance proposals",
			Severity:    5,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.rra_event_type",
				Operator: "eq",
				Value:    "proposal_executed",
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "governance_monitoring",
			},
		},

		// RRA-009: Rate Limit Triggered
		{
			ID:          "RRA-009",
			Name:        "Rate Limit Triggered",
			Description: "Detects rate limiting indicating potential abuse",
			Severity:    6,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.rra_event_type",
				Operator: "eq",
				Value:    "rate_limit",
			},
			Correlation: &correlation.CorrelationConfig{
				Type:      "threshold",
				Threshold: 5,
				Window:    "5m",
				GroupBy:   []string{"metadata.rra_source_ip"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack", "webhook"}}},
			},
			Metadata: map[string]any{
				"mitre_attack": []string{"T1499"},
				"category":     "abuse_detection",
			},
		},

		// RRA-010: Large Revenue Event
		{
			ID:          "RRA-010",
			Name:        "Large Revenue Event",
			Description: "Detects large revenue distributions",
			Severity:    4,
			Enabled:     true,
			Condition: correlation.Condition{
				Field:    "metadata.rra_amount",
				Operator: "gte",
				Value:    float64(50000),
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"channels": []string{"slack"}}},
			},
			Metadata: map[string]any{
				"category": "financial_monitoring",
			},
		},
	}
}
