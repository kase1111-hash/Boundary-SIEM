package medicagent

import (
	"boundary-siem/internal/correlation"
)

// DetectionRules returns Medic-Agent-specific detection rules.
func DetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// Kill Notification Monitoring
		{
			ID:          "ma-001",
			Name:        "High Volume Kill Notifications",
			Description: "Unusually high number of kill notifications from Smith",
			Severity:    7,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.kill.received"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   50,
				Window:  300, // 50 kills in 5 minutes
				GroupBy: []string{"metadata.ma_smith_node_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "ma-002",
			Name:        "Kill Rejected by Assessment",
			Description: "Kill notification was rejected as invalid",
			Severity:    6,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.kill.rejected"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ma_kill_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Risk Assessment Rules
		{
			ID:          "ma-003",
			Name:        "High Risk Score Assessment",
			Description: "Assessment returned high risk score",
			Severity:    8,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeCustom,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "ma.verdict"},
					{Field: "metadata.ma_risk_score", Operator: "gte", Value: 0.8},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "ma-004",
			Name:        "Suspicious Kill Verdict",
			Description: "Assessment marked kill as suspicious",
			Severity:    7,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.verdict.suspicious"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ma_kill_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "ma-005",
			Name:        "Multiple Invalid Verdicts",
			Description: "Multiple kills marked as invalid from same source",
			Severity:    8,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.verdict.invalid"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   3,
				Window:  600, // 3 invalid verdicts in 10 minutes
				GroupBy: []string{"actor.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},

		// Resurrection Workflow Rules
		{
			ID:          "ma-006",
			Name:        "Resurrection Failed",
			Description: "Process resurrection attempt failed",
			Severity:    7,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.resurrection.failed"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"target.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "ma-007",
			Name:        "Repeated Resurrection Failures",
			Description: "Same process failing resurrection multiple times",
			Severity:    9,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.resurrection.failed"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   3,
				Window:  1800, // 3 failures in 30 minutes
				GroupBy: []string{"target.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "ma-008",
			Name:        "Resurrection Rejected",
			Description: "Resurrection request was rejected",
			Severity:    5,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.resurrection.rejected"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"target.id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Anomaly Detection Rules
		{
			ID:          "ma-009",
			Name:        "Kill Pattern Anomaly",
			Description: "Unusual kill pattern detected",
			Severity:    8,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.anomaly.kill_pattern"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ma_anomaly_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "ma-010",
			Name:        "Resurrection Abuse Detected",
			Description: "Possible resurrection abuse pattern",
			Severity:    9,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.anomaly.resurrection_abuse"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ma_anomaly_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "ma-011",
			Name:        "Threshold Violation Anomaly",
			Description: "System threshold violation detected",
			Severity:    7,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.anomaly.threshold_violation"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ma_anomaly_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},

		// Rollback Rules
		{
			ID:          "ma-012",
			Name:        "Resurrection Rolled Back",
			Description: "A resurrection was rolled back",
			Severity:    6,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.rollback.completed"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ma_resurrection_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
		{
			ID:          "ma-013",
			Name:        "Rollback Failed",
			Description: "Resurrection rollback failed",
			Severity:    8,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.rollback.failed"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ma_resurrection_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},

		// Approval Workflow Rules
		{
			ID:          "ma-014",
			Name:        "Approval Timeout",
			Description: "Resurrection approval timed out",
			Severity:    6,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.approval.timeout"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ma_workflow_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
		{
			ID:          "ma-015",
			Name:        "Multiple Approval Escalations",
			Description: "Multiple approvals being escalated",
			Severity:    5,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.approval.escalated"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   5,
				Window:  600, // 5 escalations in 10 minutes
				GroupBy: []string{},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Smith Integration Rules
		{
			ID:          "ma-016",
			Name:        "Smith Connection Error",
			Description: "Error communicating with Smith node",
			Severity:    7,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.smith.error"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ma_smith_node_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "ma-017",
			Name:        "Smith Node Disconnected",
			Description: "Smith node disconnected from Medic-Agent",
			Severity:    6,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ma.smith.disconnected"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ma_smith_node_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
		{
			ID:          "ma-018",
			Name:        "High Smith Latency",
			Description: "High latency in Smith communication",
			Severity:    5,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeCustom,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "ma.smith"},
					{Field: "metadata.ma_latency_ms", Operator: "gt", Value: 5000},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Threshold Adjustment Rules
		{
			ID:          "ma-019",
			Name:        "Frequent Threshold Adjustments",
			Description: "Thresholds being adjusted frequently",
			Severity:    5,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "ma.threshold"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   10,
				Window:  3600, // 10 adjustments in 1 hour
				GroupBy: []string{},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
		{
			ID:          "ma-020",
			Name:        "Major Threshold Change",
			Description: "Large threshold value change detected",
			Severity:    6,
			Category:    "MedicAgent",
			Type:        correlation.RuleTypeCustom,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "ma.threshold"},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
	}
}
