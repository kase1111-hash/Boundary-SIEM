package longhome

import (
	"boundary-siem/internal/correlation"
)

// DetectionRules returns Long-Home-specific detection rules.
func DetectionRules() []correlation.Rule {
	return []correlation.Rule{
		// Physics Anomaly Detection (Anti-Cheat)
		{
			ID:          "lh-001",
			Name:        "Velocity Violation Detected",
			Description: "Player velocity exceeded physical limits, potential speed hack",
			Severity:    8,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "lh.physics.velocity_violation"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.lh_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "lh-002",
			Name:        "Impossible Position Detected",
			Description: "Player reached impossible position, potential teleport hack",
			Severity:    9,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "lh.physics.impossible_position"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.lh_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},
		{
			ID:          "lh-003",
			Name:        "Terrain Clipping Detected",
			Description: "Player clipped through terrain, potential noclip hack",
			Severity:    8,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "lh.physics.terrain_clip"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   2,
				Window:  300,
				GroupBy: []string{"metadata.lh_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "critical"}},
			},
		},

		// Save File Integrity
		{
			ID:          "lh-004",
			Name:        "Save File Modified Externally",
			Description: "Save file was modified outside the game, potential cheating",
			Severity:    7,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "lh.save.modified"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.lh_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
		{
			ID:          "lh-005",
			Name:        "Corrupted Save Data",
			Description: "Save file corruption detected",
			Severity:    6,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "lh.save.corrupted"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.lh_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Input Validation
		{
			ID:          "lh-006",
			Name:        "Invalid Input Detected",
			Description: "Player submitted invalid input during high-risk action",
			Severity:    5,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "lh.input.invalid"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   3,
				Window:  600,
				GroupBy: []string{"metadata.lh_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},
		{
			ID:          "lh-007",
			Name:        "Critical Risk Input",
			Description: "Player performed action with critical risk level",
			Severity:    5,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "lh.input.risky"},
					{Field: "metadata.lh_risk_level", Operator: "eq", Value: "critical"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.lh_session_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Slide Mechanics Monitoring
		{
			ID:          "lh-008",
			Name:        "Control Lost During Slide",
			Description: "Player completely lost control during slide",
			Severity:    4,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "lh.slide.control_lost"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.lh_session_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "low"}},
			},
		},
		{
			ID:          "lh-009",
			Name:        "Repeated Control Loss",
			Description: "Player repeatedly losing control, may indicate difficulty or exploit",
			Severity:    5,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "lh.slide.control_lost"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   5,
				Window:  600,
				GroupBy: []string{"metadata.lh_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Rope System Safety
		{
			ID:          "lh-010",
			Name:        "Rope Break Event",
			Description: "Player rope broke during descent",
			Severity:    6,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "lh.rope.break"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.lh_session_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Fatal Event Tracking
		{
			ID:          "lh-011",
			Name:        "Fatal Fall Event",
			Description: "Player died from a fall",
			Severity:    4,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "lh.fatal.fall"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.lh_session_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "low"}},
			},
		},
		{
			ID:          "lh-012",
			Name:        "Repeated Deaths",
			Description: "Player died multiple times in short period",
			Severity:    4,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "lh.fatal"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   5,
				Window:  1800, // 30 minutes
				GroupBy: []string{"metadata.lh_player_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Body Condition Critical
		{
			ID:          "lh-013",
			Name:        "Critical Body Condition",
			Description: "Player body condition reached critical state",
			Severity:    5,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "lh.body.critical"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   1,
				Window:  60,
				GroupBy: []string{"metadata.lh_session_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "medium"}},
			},
		},

		// Unusual Event Bus Signals
		{
			ID:          "lh-014",
			Name:        "Unusual Event Bus Activity",
			Description: "Unusual event bus signals detected, potential exploit",
			Severity:    6,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "eq", Value: "lh.signal.unusual"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   5,
				Window:  300,
				GroupBy: []string{"metadata.lh_session_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},

		// State Transition Anomalies
		{
			ID:          "lh-015",
			Name:        "Rapid State Transitions",
			Description: "Abnormally rapid state transitions, potential exploit",
			Severity:    6,
			Category:    "LongHome",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Conditions: correlation.Conditions{
				Match: []correlation.MatchCondition{
					{Field: "action", Operator: "prefix", Value: "lh.state"},
				},
			},
			Threshold: &correlation.ThresholdConfig{
				Count:   20,
				Window:  60, // 20 transitions in 1 minute
				GroupBy: []string{"metadata.lh_session_id"},
			},
			Actions: []correlation.Action{
				{Type: "alert", Config: map[string]any{"priority": "high"}},
			},
		},
	}
}
