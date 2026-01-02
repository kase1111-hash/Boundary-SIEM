// Package correlation provides event correlation and detection capabilities.
package correlation

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// RuleType defines the type of correlation rule.
type RuleType string

const (
	// RuleTypeThreshold fires when event count exceeds threshold in window.
	RuleTypeThreshold RuleType = "threshold"
	// RuleTypeSequence fires when events occur in specific order.
	RuleTypeSequence RuleType = "sequence"
	// RuleTypeAggregate fires based on aggregated values.
	RuleTypeAggregate RuleType = "aggregate"
	// RuleTypeAbsence fires when expected event is missing.
	RuleTypeAbsence RuleType = "absence"
	// RuleTypeCustom for custom rule logic.
	RuleTypeCustom RuleType = "custom"
)

// Severity levels for rules.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Rule represents a correlation rule definition.
type Rule struct {
	ID          string               `yaml:"id"`
	Name        string               `yaml:"name"`
	Description string               `yaml:"description"`
	Type        RuleType             `yaml:"type"`
	Enabled     bool                 `yaml:"enabled"`
	Severity    int                  `yaml:"severity"`
	Category    string               `yaml:"category,omitempty"`
	Tags        []string             `yaml:"tags,omitempty"`
	MITRE       *MITREMapping        `yaml:"mitre,omitempty"`
	Conditions  Conditions           `yaml:"conditions"`
	Condition   Condition             `yaml:"condition,omitempty"`   // Alternative single condition
	GroupBy     []string             `yaml:"group_by,omitempty"`
	Window      time.Duration        `yaml:"window"`
	Threshold   *ThresholdConfig     `yaml:"threshold,omitempty"`
	Sequence    *SequenceConfig      `yaml:"sequence,omitempty"`
	Aggregate   *AggregateConfig     `yaml:"aggregate,omitempty"`
	Absence     *AbsenceConfig       `yaml:"absence,omitempty"`
	Correlation *CorrelationConfig   `yaml:"correlation,omitempty"` // For correlation rules
	Actions     []Action             `yaml:"actions,omitempty"`
	Metadata    map[string]any       `yaml:"metadata,omitempty"`
}

// Conditions holds match conditions for a rule.
type Conditions struct {
	Match []MatchCondition `yaml:"match,omitempty"`
}

// MatchCondition represents a field match condition.
type MatchCondition struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"`
	Value    any    `yaml:"value"`
}

// Action represents an action to take when a rule fires.
type Action struct {
	Type   string         `yaml:"type"`
	Config map[string]any `yaml:"config,omitempty"`
}

// MITREMapping maps the rule to MITRE ATT&CK.
type MITREMapping struct {
	TacticID    string   `yaml:"tactic_id"`
	TacticName  string   `yaml:"tactic_name"`
	TechniqueID string   `yaml:"technique_id"`
	Techniques  []string `yaml:"techniques,omitempty"`
}

// Condition represents a filter condition for events.
type Condition struct {
	Field    string      `yaml:"field"`
	Operator string      `yaml:"operator"` // eq, ne, gt, gte, lt, lte, contains, regex, in
	Value    any         `yaml:"value"`
	Values   []string    `yaml:"values,omitempty"` // For "in" operator
	And      []Condition `yaml:"and,omitempty"`    // AND combination of conditions
	Or       []Condition `yaml:"or,omitempty"`     // OR combination of conditions
}

// ThresholdConfig defines threshold-based correlation settings.
type ThresholdConfig struct {
	Count    int      `yaml:"count"`
	Window   int      `yaml:"window,omitempty"`   // Window in seconds
	GroupBy  []string `yaml:"group_by,omitempty"` // Fields to group by
	Operator string   `yaml:"operator"`           // gt, gte, lt, lte, eq
}

// SequenceConfig defines sequence-based correlation settings.
type SequenceConfig struct {
	Ordered  bool           `yaml:"ordered"`
	MaxSpan  time.Duration  `yaml:"max_span"`
	Steps    []SequenceStep `yaml:"steps"`
	Events   []SequenceEvent `yaml:"events,omitempty"`  // Alternative to Steps
	Window   int             `yaml:"window,omitempty"`   // Window in seconds
	GroupBy  []string        `yaml:"group_by,omitempty"` // Fields to group by
}

// SequenceStep represents one step in a sequence.
type SequenceStep struct {
	Name       string      `yaml:"name"`
	Conditions []Condition `yaml:"conditions"`
	Required   bool        `yaml:"required"`
}

// SequenceEvent represents an event in a sequence (alternative to SequenceStep).
type SequenceEvent struct {
	ID         string           `yaml:"id"`
	Conditions []MatchCondition `yaml:"conditions"`
}

// AggregateConfig defines aggregate-based correlation settings.
type AggregateConfig struct {
	Function  string   `yaml:"function"` // sum, avg, min, max, count_distinct
	Field     string   `yaml:"field"`
	Operator  string   `yaml:"operator"`
	Value     float64  `yaml:"value"`
	Threshold float64  `yaml:"threshold,omitempty"`
	Window    int      `yaml:"window,omitempty"`
	GroupBy   []string `yaml:"group_by,omitempty"`
}

// AbsenceConfig defines absence-based correlation settings.
type AbsenceConfig struct {
	ExpectedConditions []Condition   `yaml:"expected_conditions"`
	AfterConditions    []Condition   `yaml:"after_conditions,omitempty"`
	Timeout            time.Duration `yaml:"timeout"`
	Window             int           `yaml:"window,omitempty"`
	GroupBy            []string      `yaml:"group_by,omitempty"`
}

// CorrelationConfig defines cross-event correlation settings.
type CorrelationConfig struct {
	Type      string   `yaml:"type,omitempty"`       // threshold, sequence, etc.
	Window    string   `yaml:"window,omitempty"`     // Duration string like "30m"
	Threshold int      `yaml:"threshold,omitempty"`  // Threshold count
	GroupBy   []string `yaml:"group_by,omitempty"`
	MinHits   int      `yaml:"min_hits,omitempty"`
}

// ActionConfig defines actions to take when rule fires.
type ActionConfig struct {
	Type   string         `yaml:"type"` // alert, webhook, log, suppress
	Config map[string]any `yaml:"config,omitempty"`
}

// Validate validates the rule configuration.
func (r *Rule) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if r.Type == "" {
		return fmt.Errorf("rule type is required")
	}

	switch r.Type {
	case RuleTypeThreshold:
		if r.Threshold == nil {
			return fmt.Errorf("threshold config required for threshold rules")
		}
		if r.Threshold.Count <= 0 {
			return fmt.Errorf("threshold count must be positive")
		}
	case RuleTypeSequence:
		if r.Sequence == nil {
			return fmt.Errorf("sequence config required for sequence rules")
		}
		if len(r.Sequence.Steps) < 2 {
			return fmt.Errorf("sequence rules require at least 2 steps")
		}
	case RuleTypeAggregate:
		if r.Aggregate == nil {
			return fmt.Errorf("aggregate config required for aggregate rules")
		}
	case RuleTypeAbsence:
		if r.Absence == nil {
			return fmt.Errorf("absence config required for absence rules")
		}
	case RuleTypeCustom:
		// Custom rules have no specific requirements
	default:
		return fmt.Errorf("unknown rule type: %s", r.Type)
	}

	// Validate match conditions
	for i, cond := range r.Conditions.Match {
		if cond.Field == "" {
			return fmt.Errorf("match condition %d: field is required", i)
		}
		if cond.Operator == "" {
			return fmt.Errorf("match condition %d: operator is required", i)
		}
	}

	return nil
}

// Validate validates a condition.
func (c *Condition) Validate() error {
	if c.Field == "" {
		return fmt.Errorf("field is required")
	}
	if c.Operator == "" {
		return fmt.Errorf("operator is required")
	}

	validOps := map[string]bool{
		"eq": true, "ne": true, "gt": true, "gte": true,
		"lt": true, "lte": true, "contains": true,
		"regex": true, "in": true, "not_in": true,
		"exists": true, "not_exists": true,
	}
	if !validOps[c.Operator] {
		return fmt.Errorf("invalid operator: %s", c.Operator)
	}

	if c.Operator == "in" || c.Operator == "not_in" {
		if len(c.Values) == 0 {
			return fmt.Errorf("values required for %s operator", c.Operator)
		}
	}

	return nil
}

// Match checks if an event matches this condition.
func (c *Condition) Match(eventValue any) bool {
	switch c.Operator {
	case "eq":
		return c.matchEquals(eventValue)
	case "ne":
		return !c.matchEquals(eventValue)
	case "gt":
		return c.matchCompare(eventValue) > 0
	case "gte":
		return c.matchCompare(eventValue) >= 0
	case "lt":
		return c.matchCompare(eventValue) < 0
	case "lte":
		return c.matchCompare(eventValue) <= 0
	case "contains":
		return c.matchContains(eventValue)
	case "regex":
		return c.matchRegex(eventValue)
	case "in":
		return c.matchIn(eventValue)
	case "not_in":
		return !c.matchIn(eventValue)
	case "exists":
		return eventValue != nil && eventValue != ""
	case "not_exists":
		return eventValue == nil || eventValue == ""
	}
	return false
}

func (c *Condition) matchEquals(eventValue any) bool {
	// Handle string comparison
	if strVal, ok := eventValue.(string); ok {
		if condVal, ok := c.Value.(string); ok {
			return strVal == condVal
		}
	}
	// Handle numeric comparison
	if numVal, ok := toFloat64(eventValue); ok {
		if condVal, ok := toFloat64(c.Value); ok {
			return numVal == condVal
		}
	}
	return fmt.Sprintf("%v", eventValue) == fmt.Sprintf("%v", c.Value)
}

func (c *Condition) matchCompare(eventValue any) int {
	numVal, ok1 := toFloat64(eventValue)
	condVal, ok2 := toFloat64(c.Value)
	if !ok1 || !ok2 {
		// Fall back to string comparison
		str1 := fmt.Sprintf("%v", eventValue)
		str2 := fmt.Sprintf("%v", c.Value)
		return strings.Compare(str1, str2)
	}
	if numVal < condVal {
		return -1
	}
	if numVal > condVal {
		return 1
	}
	return 0
}

func (c *Condition) matchContains(eventValue any) bool {
	str := fmt.Sprintf("%v", eventValue)
	pattern := fmt.Sprintf("%v", c.Value)
	return strings.Contains(strings.ToLower(str), strings.ToLower(pattern))
}

func (c *Condition) matchRegex(eventValue any) bool {
	str := fmt.Sprintf("%v", eventValue)
	pattern := fmt.Sprintf("%v", c.Value)
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(str)
}

func (c *Condition) matchIn(eventValue any) bool {
	str := fmt.Sprintf("%v", eventValue)
	for _, v := range c.Values {
		if str == v {
			return true
		}
	}
	return false
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	case string:
		// Try parsing
		var f float64
		if _, err := fmt.Sscanf(n, "%f", &f); err == nil {
			return f, true
		}
	}
	return 0, false
}

// ParseRule parses a rule from YAML bytes.
func ParseRule(data []byte) (*Rule, error) {
	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("failed to parse rule: %w", err)
	}
	if err := rule.Validate(); err != nil {
		return nil, fmt.Errorf("invalid rule: %w", err)
	}
	return &rule, nil
}

// ParseRules parses multiple rules from YAML bytes.
func ParseRules(data []byte) ([]*Rule, error) {
	var rules []*Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		// Try single rule format
		rule, singleErr := ParseRule(data)
		if singleErr != nil {
			return nil, fmt.Errorf("failed to parse rules: %w", err)
		}
		return []*Rule{rule}, nil
	}

	for i, rule := range rules {
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return rules, nil
}

// SeverityToInt converts severity to numeric value.
func SeverityToInt(s Severity) int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 4
	case SeverityHigh:
		return 7
	case SeverityCritical:
		return 10
	default:
		return 5
	}
}
