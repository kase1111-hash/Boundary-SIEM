package natlangchain

import (
	"boundary-siem/internal/correlation"
)

// DetectionRules returns NatLangChain-specific detection rules.
func DetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// Semantic Drift Detection
		{
			ID:          "nlc-001",
			Name:        "Critical Semantic Drift Detected",
			Description: "A critical semantic drift was detected, indicating significant interpretation divergence",
			Severity:    9,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.semantic.drift.critical"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  300, // 5 minutes
				GroupBy: []string{"metadata.nlc_entry_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "nlc-002",
			Name:        "High Semantic Drift Volume",
			Description: "Multiple semantic drifts detected in a short period, may indicate systematic manipulation",
			Severity:    7,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "nlc.semantic.drift"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   10,
				Window:  600, // 10 minutes
				GroupBy: []string{"source.instance_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},

		// Dispute Escalation
		{
			ID:          "nlc-003",
			Name:        "Dispute Escalation",
			Description: "A dispute has been escalated, indicating unresolved conflict",
			Severity:    7,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.dispute.escalated"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.nlc_dispute_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "nlc-004",
			Name:        "Dispute Storm",
			Description: "Multiple disputes filed in rapid succession, may indicate coordinated attack",
			Severity:    8,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.dispute.filed"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   5,
				Window:  300, // 5 minutes
				GroupBy: []string{"actor.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},

		// Entry Validation Failures
		{
			ID:          "nlc-005",
			Name:        "Entry Rejection",
			Description: "An entry was rejected by validators",
			Severity:    5,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.entry.rejected"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.nlc_entry_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
		{
			ID:          "nlc-006",
			Name:        "Repeated Entry Rejections",
			Description: "Multiple entries from the same author were rejected",
			Severity:    7,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.entry.rejected"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   3,
				Window:  3600, // 1 hour
				GroupBy: []string{"actor.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},

		// Validation Consensus Issues
		{
			ID:          "nlc-007",
			Name:        "Validation Rejection",
			Description: "A validation was rejected during the consensus process",
			Severity:    6,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.validation.rejection"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.nlc_entry_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
		{
			ID:          "nlc-008",
			Name:        "Validator Debate Failure",
			Description: "Dialectic debate between validators resulted in rejection",
			Severity:    5,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.validation.debate"},
					{Field: "outcome", Operator: "eq", Value: "failure"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.nlc_entry_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Negotiation Failures
		{
			ID:          "nlc-009",
			Name:        "Negotiation Failure",
			Description: "A negotiation session failed or timed out",
			Severity:    4,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "in", Value: []string{"nlc.negotiation.failed", "nlc.negotiation.timeout"}},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.nlc_negotiation_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "low"}},
			},
		},
		{
			ID:          "nlc-010",
			Name:        "Negotiation Failure Spike",
			Description: "Multiple negotiation failures in short period",
			Severity:    6,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "in", Value: []string{"nlc.negotiation.failed", "nlc.negotiation.timeout"}},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   5,
				Window:  600, // 10 minutes
				GroupBy: []string{"source.instance_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},

		// Contract Anomalies
		{
			ID:          "nlc-011",
			Name:        "Contract Cancellation",
			Description: "A contract was cancelled",
			Severity:    4,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.contract.cancelled"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.nlc_contract_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "low"}},
			},
		},
		{
			ID:          "nlc-012",
			Name:        "Mass Contract Cancellation",
			Description: "Multiple contracts cancelled by the same user",
			Severity:    7,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.contract.cancelled"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   3,
				Window:  3600, // 1 hour
				GroupBy: []string{"actor.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},

		// Chain Health
		{
			ID:          "nlc-013",
			Name:        "Block Production Stall",
			Description: "No new blocks mined in expected time window",
			Severity:    8,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeAbsence,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.block.mined"},
				},
			},
			Absence: &correlation.AbsenceConfig{
				Window:  600, // 10 minutes without a block
				GroupBy: []string{"source.instance_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "nlc-014",
			Name:        "Low Validation Confidence",
			Description: "Validation with unusually low confidence score",
			Severity:    5,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeCustom,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "nlc.validation"},
					{Field: "metadata.nlc_confidence", Operator: "lt", Value: 0.5},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Security Events
		{
			ID:          "nlc-015",
			Name:        "Adversarial Pattern Detected",
			Description: "Potential adversarial content or manipulation attempt detected",
			Severity:    9,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.security.adversarial"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"actor.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "nlc-016",
			Name:        "Content Manipulation Attempt",
			Description: "Potential semantic manipulation or injection attempt",
			Severity:    8,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.security.manipulation"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"actor.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "nlc-017",
			Name:        "Identity Impersonation Attempt",
			Description: "Potential identity impersonation or spoofing attempt",
			Severity:    9,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.security.impersonation"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"actor.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},

		// Anomaly Detection
		{
			ID:          "nlc-018",
			Name:        "Unusual Entry Volume",
			Description: "Abnormally high volume of entries from a single author",
			Severity:    6,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.entry.created"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   50,
				Window:  3600, // 1 hour
				GroupBy: []string{"actor.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "nlc-019",
			Name:        "Rapid Dispute Resolution",
			Description: "Dispute resolved suspiciously quickly after filing",
			Severity:    5,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "source.product", Operator: "eq", Value: "natlangchain"},
				},
			},
			Sequence: &correlation.SequenceConfig{
				Events: []correlation.SequenceEvent{
					{
						ID: "dispute_filed",
						Conditions: []correlation.MatchCondition{
							{Field: "action", Operator: "eq", Value: "nlc.dispute.filed"},
						},
					},
					{
						ID: "dispute_resolved",
						Conditions: []correlation.MatchCondition{
							{Field: "action", Operator: "eq", Value: "nlc.dispute.resolved"},
						},
					},
				},
				Window:  60, // Resolved within 1 minute
				Ordered: true,
				GroupBy: []string{"metadata.nlc_dispute_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
		{
			ID:          "nlc-020",
			Name:        "Validator Misbehavior",
			Description: "Same validator rejecting multiple entries in short period",
			Severity:    7,
			Category:    "NatLangChain",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "nlc.validation.rejection"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   10,
				Window:  600, // 10 minutes
				GroupBy: []string{"metadata.nlc_validator_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
	}
}
