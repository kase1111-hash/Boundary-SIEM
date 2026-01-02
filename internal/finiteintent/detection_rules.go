package finiteintent

import (
	"boundary-siem/internal/correlation"
)

// DetectionRules returns Finite Intent Executor-specific detection rules.
func DetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// Trigger Validation Issues
		{
			ID:          "fie-001",
			Name:        "Trigger Validation Rejected",
			Description: "A trigger activation was rejected, intent will not execute",
			Severity:    7,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.trigger.rejected"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "fie-002",
			Name:        "Multiple Trigger Failures",
			Description: "Multiple trigger activations failed for the same intent",
			Severity:    8,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "in", Value: []string{"fie.trigger.rejected", "fie.trigger.expired"}},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   3,
				Window:  3600,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},

		// Execution Agent Blocks
		{
			ID:          "fie-003",
			Name:        "Execution Blocked - Political Content",
			Description: "Execution agent blocked action due to political content detection",
			Severity:    8,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.execution.blocked"},
					{Field: "metadata.fie_blocked_reason", Operator: "eq", Value: "political_content"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "fie-004",
			Name:        "Low Confidence Execution",
			Description: "Execution agent decision made with confidence below 95% threshold",
			Severity:    6,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeCustom,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "fie.execution"},
					{Field: "metadata.fie_confidence", Operator: "lt", Value: 0.95},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
		{
			ID:          "fie-005",
			Name:        "Execution Constraint Violation",
			Description: "Execution blocked due to constraint violation",
			Severity:    7,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.execution.blocked"},
					{Field: "metadata.fie_blocked_reason", Operator: "eq", Value: "constraint_violation"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},

		// Oracle Issues
		{
			ID:          "fie-006",
			Name:        "Oracle Response Disputed",
			Description: "An oracle response was disputed, may affect intent execution",
			Severity:    7,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.oracle.disputed"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.fie_oracle_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "fie-007",
			Name:        "Oracle Timeout",
			Description: "Oracle verification timed out, trigger may be delayed",
			Severity:    6,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.oracle.timeout"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// IP Token Security
		{
			ID:          "fie-008",
			Name:        "IP Token Revoked",
			Description: "An intellectual property token was revoked",
			Severity:    7,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.ip.revoked"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.fie_token_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "fie-009",
			Name:        "Rapid IP Transfers",
			Description: "Multiple IP token transfers in short period, potential unauthorized activity",
			Severity:    8,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.ip.transferred"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   5,
				Window:  300,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},

		// Security Events
		{
			ID:          "fie-010",
			Name:        "Security Constraint Violation",
			Description: "A security constraint was violated",
			Severity:    9,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.security.constraint_violation"},
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
			ID:          "fie-011",
			Name:        "Security Anomaly Detected",
			Description: "An anomalous security pattern was detected",
			Severity:    8,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.security.anomaly"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "fie-012",
			Name:        "Unauthorized Access Change",
			Description: "Access permissions were changed without proper authorization",
			Severity:    8,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.security.access_change"},
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

		// Intent Lifecycle Anomalies
		{
			ID:          "fie-013",
			Name:        "Intent Modified After Activation",
			Description: "An intent was modified after being activated, potential tampering",
			Severity:    9,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "source.product", Operator: "eq", Value: "finite-intent-executor"},
				},
			},
			Sequence: &correlation.SequenceConfig{
				Events: []correlation.SequenceEvent{
					{
						ID: "activated",
						Conditions: []correlation.MatchCondition{
							{Field: "action", Operator: "eq", Value: "fie.intent.activated"},
						},
					},
					{
						ID: "modified",
						Conditions: []correlation.MatchCondition{
							{Field: "action", Operator: "eq", Value: "fie.intent.modified"},
						},
					},
				},
				Window:  86400, // 24 hours
				Ordered: true,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},

		// Sunset Protocol
		{
			ID:          "fie-014",
			Name:        "Sunset Process Initiated",
			Description: "20-year sunset process has begun for an intent",
			Severity:    4,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.sunset.initiated"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "low"}},
			},
		},
		{
			ID:          "fie-015",
			Name:        "Public Domain Transition Complete",
			Description: "Assets have transitioned to public domain",
			Severity:    3,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.sunset.complete"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "low"}},
			},
		},

		// Deadman Switch Alerts
		{
			ID:          "fie-016",
			Name:        "Deadman Switch Activated",
			Description: "A deadman switch trigger was activated due to inactivity",
			Severity:    6,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.trigger.deadman"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},

		// Quorum Voting
		{
			ID:          "fie-017",
			Name:        "Quorum Trigger Activated",
			Description: "A trusted quorum has voted to activate an intent",
			Severity:    5,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.trigger.quorum"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Content Hash Verification
		{
			ID:          "fie-018",
			Name:        "Intent Hash Mismatch",
			Description: "Content hash verification failed, potential tampering",
			Severity:    9,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.security.constraint_violation"},
					{Field: "raw", Operator: "contains", Value: "hash"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},

		// Execution Failure Patterns
		{
			ID:          "fie-019",
			Name:        "Repeated Execution Failures",
			Description: "Multiple execution failures for the same intent",
			Severity:    7,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "outcome", Operator: "eq", Value: "failure"},
					{Field: "action", Operator: "prefix", Value: "fie.execution"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   3,
				Window:  3600,
				GroupBy: []string{"metadata.fie_intent_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},

		// Role Assignment Monitoring
		{
			ID:          "fie-020",
			Name:        "Critical Role Assignment",
			Description: "A critical role was assigned, requires audit",
			Severity:    6,
			Category:    "FiniteIntentExecutor",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "fie.security.role_assignment"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"actor.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
	}
}
