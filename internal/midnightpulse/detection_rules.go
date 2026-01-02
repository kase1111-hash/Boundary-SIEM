package midnightpulse

import (
	"boundary-siem/internal/correlation"
)

// DetectionRules returns Midnight Pulse-specific detection rules.
func DetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// Input Anomaly Detection (Anti-Cheat)
		{
			ID:          "mp-001",
			Name:        "Macro Input Detected",
			Description: "Automated macro input pattern detected, potential cheating",
			Severity:    8,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "mp.anomaly.macro_detected"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.mp_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "mp-002",
			Name:        "Impossible Input Sequence",
			Description: "Input sequence physically impossible for human player",
			Severity:    9,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "mp.anomaly.impossible_sequence"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.mp_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "mp-003",
			Name:        "Repeated Input Anomalies",
			Description: "Multiple input anomalies from the same player",
			Severity:    8,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "mp.anomaly"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   3,
				Window:  3600,
				GroupBy: []string{"metadata.mp_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},

		// Leaderboard Integrity
		{
			ID:          "mp-004",
			Name:        "Suspicious Leaderboard Score",
			Description: "Leaderboard submission flagged as suspicious",
			Severity:    7,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "mp.leaderboard.suspicious"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.mp_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "mp-005",
			Name:        "Rapid Score Improvements",
			Description: "Player score improved abnormally fast",
			Severity:    6,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "mp.leaderboard.submitted"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   10,
				Window:  3600, // 10 submissions in 1 hour
				GroupBy: []string{"metadata.mp_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Save Data Integrity
		{
			ID:          "mp-006",
			Name:        "Corrupted Save Data",
			Description: "Save file corruption detected, potential tampering",
			Severity:    6,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "mp.saveload.corrupted"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.mp_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
		{
			ID:          "mp-007",
			Name:        "Repeated Save Corruption",
			Description: "Multiple save file corruptions for same player",
			Severity:    7,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "mp.saveload.corrupted"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   3,
				Window:  86400, // 3 corruptions in 24 hours
				GroupBy: []string{"metadata.mp_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},

		// Performance Issues
		{
			ID:          "mp-008",
			Name:        "Severe Performance Degradation",
			Description: "Critical frame rate or memory issues detected",
			Severity:    5,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "in", Value: []string{"mp.performance.frame_drop", "mp.performance.memory_spike"}},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   5,
				Window:  600, // 5 issues in 10 minutes
				GroupBy: []string{"metadata.mp_session_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Session Anomalies
		{
			ID:          "mp-009",
			Name:        "Abnormal Session Duration",
			Description: "Session lasted unusually long or short",
			Severity:    4,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeCustom,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "mp.session.completed"},
					{Field: "metadata.mp_duration", Operator: "gt", Value: 43200}, // > 12 hours
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "low"}},
			},
		},
		{
			ID:          "mp-010",
			Name:        "High Disconnect Rate",
			Description: "Player has high rate of disconnected sessions",
			Severity:    5,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "mp.session.disconnected"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   5,
				Window:  3600,
				GroupBy: []string{"metadata.mp_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Multiplayer Fair Play
		{
			ID:          "mp-011",
			Name:        "Ghost Race Abandonment Pattern",
			Description: "Player frequently abandoning ghost races when losing",
			Severity:    5,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "mp.multiplayer.ghost_race_complete"},
					{Field: "metadata.mp_outcome", Operator: "eq", Value: "abandoned"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   5,
				Window:  3600,
				GroupBy: []string{"metadata.mp_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Timing Anomalies
		{
			ID:          "mp-012",
			Name:        "Input Timing Anomaly",
			Description: "Suspicious input timing patterns detected",
			Severity:    6,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "mp.anomaly.timing_anomaly"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   3,
				Window:  600,
				GroupBy: []string{"metadata.mp_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},

		// Crash Pattern Analysis
		{
			ID:          "mp-013",
			Name:        "Unusual Crash Pattern",
			Description: "Player crashes at suspicious times or locations",
			Severity:    4,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "source.product", Operator: "eq", Value: "midnight-pulse"},
				},
			},
			Sequence: &correlation.SequenceConfig{
				Events: []correlation.SequenceEvent{
					{
						ID: "high_score_approach",
						Conditions: []correlation.MatchCondition{
							{Field: "action", Operator: "eq", Value: "mp.leaderboard.submitted"},
						},
					},
					{
						ID: "immediate_crash",
						Conditions: []correlation.MatchCondition{
							{Field: "action", Operator: "prefix", Value: "mp.crash"},
						},
					},
				},
				Window:  30, // Crash within 30 seconds of score
				Ordered: true,
				GroupBy: []string{"metadata.mp_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// High Confidence Anomalies
		{
			ID:          "mp-014",
			Name:        "High Confidence Cheat Detection",
			Description: "Anomaly detected with high confidence score",
			Severity:    9,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeCustom,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "mp.anomaly"},
					{Field: "metadata.mp_confidence", Operator: "gt", Value: 0.95},
				},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},

		// Rapid Input Detection
		{
			ID:          "mp-015",
			Name:        "Rapid Input Detection",
			Description: "Abnormally rapid input detected",
			Severity:    6,
			Category:    "MidnightPulse",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "mp.anomaly.rapid_input"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   2,
				Window:  300,
				GroupBy: []string{"metadata.mp_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
	}
}
