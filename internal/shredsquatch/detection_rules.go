package shredsquatch

import (
	"boundary-siem/internal/correlation"
)

// DetectionRules returns Shredsquatch-specific detection rules.
func DetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// Input Anomaly Detection (Anti-Cheat)
		{
			ID:          "ss-001",
			Name:        "Impossible Trick Detected",
			Description: "Player performed a physically impossible trick combination",
			Severity:    9,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ss.anomaly.impossible_trick"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ss_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "ss-002",
			Name:        "Timing Exploit Detected",
			Description: "Player exploiting timing mechanics",
			Severity:    8,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ss.anomaly.timing_exploit"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ss_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "ss-003",
			Name:        "Rapid Input Anomaly",
			Description: "Abnormally rapid input detected, possible macro/bot",
			Severity:    7,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ss.anomaly.rapid_input"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   2,
				Window:  300,
				GroupBy: []string{"metadata.ss_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},

		// Leaderboard Integrity
		{
			ID:          "ss-004",
			Name:        "Suspicious Leaderboard Score",
			Description: "Leaderboard submission flagged as suspicious",
			Severity:    7,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ss.leaderboard.suspicious"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ss_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "ss-005",
			Name:        "Rapid Score Submissions",
			Description: "Player submitting many scores in short period",
			Severity:    5,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ss.leaderboard.submitted"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   10,
				Window:  3600, // 10 submissions in 1 hour
				GroupBy: []string{"metadata.ss_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Trick Score Anomalies
		{
			ID:          "ss-006",
			Name:        "Unrealistic Trick Combo",
			Description: "Player achieved unrealistic combo length",
			Severity:    6,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeCustom,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "ss.trick"},
					{Field: "metadata.ss_combo_length", Operator: "gt", Value: 50},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "ss-007",
			Name:        "Perfect Trick Landing Rate",
			Description: "Player has suspiciously perfect trick success rate",
			Severity:    5,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeAggregate,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ss.trick.landed"},
				},
			},
			Aggregate: &correlation.AggregateConfig{
				Function:  "count",
				Field:     "event_id",
				Threshold: 100,
				Window:    3600,
				GroupBy:   []string{"metadata.ss_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Asset Loading Issues
		{
			ID:          "ss-008",
			Name:        "Asset Load Failure",
			Description: "Game asset failed to load",
			Severity:    5,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ss.asset.failed"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.ss_session_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
		{
			ID:          "ss-009",
			Name:        "Multiple Asset Failures",
			Description: "Multiple asset loading failures in session",
			Severity:    6,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ss.asset.failed"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   5,
				Window:  600,
				GroupBy: []string{"metadata.ss_session_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},

		// Performance Issues
		{
			ID:          "ss-010",
			Name:        "Severe Frame Rate Issues",
			Description: "Session experiencing severe frame rate drops",
			Severity:    4,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ss.performance.frame_drop"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   5,
				Window:  300,
				GroupBy: []string{"metadata.ss_session_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "low"}},
			},
		},

		// Sasquatch Evasion Anomalies
		{
			ID:          "ss-011",
			Name:        "Impossible Sasquatch Escape",
			Description: "Player escaped Sasquatch in suspiciously short time",
			Severity:    6,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeCustom,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ss.sasquatch.escaped"},
					{Field: "metadata.ss_chase_time", Operator: "lt", Value: 2.0},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "ss-012",
			Name:        "Never Caught by Sasquatch",
			Description: "Player has abnormally high Sasquatch escape rate",
			Severity:    5,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ss.sasquatch.escaped"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   20,
				Window:  3600,
				GroupBy: []string{"metadata.ss_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Session Anomalies
		{
			ID:          "ss-013",
			Name:        "Abnormal Run Distance",
			Description: "Player achieved abnormally high distance",
			Severity:    6,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeCustom,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "ss.run.end"},
					{Field: "metadata.ss_distance", Operator: "gt", Value: 100000},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "ss-014",
			Name:        "Impossible Max Speed",
			Description: "Player achieved impossible maximum speed",
			Severity:    8,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeCustom,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "ss.run"},
					{Field: "metadata.ss_max_speed", Operator: "gt", Value: 500},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},

		// Collision Anomalies
		{
			ID:          "ss-015",
			Name:        "No Collision Deaths",
			Description: "Player has abnormally low collision rate",
			Severity:    5,
			Category:    "Shredsquatch",
			Type:        correlation.RuleTypeAbsence,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "ss.collision"},
				},
			},
			Absence: &correlation.AbsenceConfig{
				Window:  3600, // No collisions in 1 hour of play
				GroupBy: []string{"metadata.ss_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
	}
}
