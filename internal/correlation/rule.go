// Package correlation provides event correlation and detection capabilities.
package correlation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
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

// Rule severities are integers in this range (matching schema.Event).
const (
	MinRuleSeverity = 1
	MaxRuleSeverity = 10
)

// Rule represents a correlation rule definition.
//
// The JSON form follows the dashboard contract in web/src/types/api.ts: keys
// are snake_case and windows and spans are Go duration strings such as "5m"
// (see rule_json.go).
//
// An event is evaluated by a rule only if it satisfies all of the rule's
// filters: every Conditions.Match entry, every EventConditions entry and the
// Condition tree when it is set.
type Rule struct {
	ID              string             `yaml:"id" json:"id"`
	Name            string             `yaml:"name" json:"name"`
	Description     string             `yaml:"description" json:"description"`
	Type            RuleType           `yaml:"type" json:"type"`
	Enabled         bool               `yaml:"enabled" json:"enabled"`
	Severity        int                `yaml:"severity" json:"severity"`
	Category        string             `yaml:"category,omitempty" json:"category,omitempty"`
	Tags            []string           `yaml:"tags,omitempty" json:"tags,omitempty"`
	MITRE           *MITREMapping      `yaml:"mitre,omitempty" json:"mitre,omitempty"`
	Conditions      Conditions         `yaml:"conditions" json:"conditions"`
	Condition       Condition          `yaml:"condition,omitempty" json:"condition,omitzero"`                // Alternative single condition tree
	EventConditions []Condition        `yaml:"event_conditions,omitempty" json:"event_conditions,omitempty"` // Slice of conditions for programmatic use
	GroupBy         []string           `yaml:"group_by,omitempty" json:"group_by,omitempty"`
	Window          time.Duration      `yaml:"window" json:"window"` // JSON: duration string ("5m")
	Threshold       *ThresholdConfig   `yaml:"threshold,omitempty" json:"threshold,omitempty"`
	Sequence        *SequenceConfig    `yaml:"sequence,omitempty" json:"sequence,omitempty"`
	Aggregate       *AggregateConfig   `yaml:"aggregate,omitempty" json:"aggregate,omitempty"`
	Absence         *AbsenceConfig     `yaml:"absence,omitempty" json:"absence,omitempty"`
	Correlation     *CorrelationConfig `yaml:"correlation,omitempty" json:"correlation,omitempty"` // For correlation rules
	Actions         []Action           `yaml:"actions,omitempty" json:"actions,omitempty"`
	Metadata        map[string]any     `yaml:"metadata,omitempty" json:"metadata,omitempty"`
	DependsOn       []string           `yaml:"depends_on,omitempty" json:"depends_on,omitempty"` // Rule IDs that must fire first (chaining)
	Baseline        *BaselineConfig    `yaml:"baseline,omitempty" json:"baseline,omitempty"`     // Adaptive threshold config

	// Provenance tracking — populated when rules are created/updated via API
	CreatedBy   string    `yaml:"-" json:"created_by,omitempty"`
	CreatedAt   time.Time `yaml:"-" json:"created_at,omitzero"`
	UpdatedBy   string    `yaml:"-" json:"updated_by,omitempty"`
	UpdatedAt   time.Time `yaml:"-" json:"updated_at,omitzero"`
	ContentHash string    `yaml:"-" json:"content_hash,omitempty"` // SHA256 of rule definition
}

// Conditions holds match conditions for a rule.
type Conditions struct {
	Match []MatchCondition `yaml:"match,omitempty" json:"match,omitempty"`
}

// MatchCondition represents a field match condition.
type MatchCondition struct {
	Field    string `yaml:"field" json:"field"`
	Operator string `yaml:"operator" json:"operator"`
	Value    any    `yaml:"value" json:"value"`
}

// Action represents an action to take when a rule fires.
type Action struct {
	Type   string         `yaml:"type" json:"type"`
	Config map[string]any `yaml:"config,omitempty" json:"config,omitempty"`
}

// MITREMapping maps the rule to MITRE ATT&CK.
type MITREMapping struct {
	TacticID      string   `yaml:"tactic_id" json:"tactic_id"`
	TacticName    string   `yaml:"tactic_name" json:"tactic_name"`
	TechniqueID   string   `yaml:"technique_id" json:"technique_id"`
	TechniqueName string   `yaml:"technique_name,omitempty" json:"technique_name"`
	Techniques    []string `yaml:"techniques,omitempty" json:"techniques,omitempty"`
}

// Condition represents a filter condition for events. A condition with a
// Field is a leaf test; a condition without a Field groups And/Or children.
type Condition struct {
	Field    string      `yaml:"field" json:"field,omitempty"`
	Operator string      `yaml:"operator" json:"operator,omitempty"` // one of the operators accepted by Validate
	Value    any         `yaml:"value" json:"value"`
	Values   []string    `yaml:"values,omitempty" json:"values,omitempty"` // For "in" and "not_in"
	And      []Condition `yaml:"and,omitempty" json:"and,omitempty"`       // AND combination of conditions
	Or       []Condition `yaml:"or,omitempty" json:"or,omitempty"`         // OR combination of conditions
}

// IsZero reports whether the condition is unset. YAML and JSON use it to omit
// an unused Rule.Condition, and the engine skips evaluating an unset tree.
func (c Condition) IsZero() bool {
	return c.Field == "" && c.Operator == "" && c.Value == nil &&
		len(c.Values) == 0 && len(c.And) == 0 && len(c.Or) == 0
}

// ThresholdConfig defines threshold-based correlation settings.
type ThresholdConfig struct {
	Count    int      `yaml:"count" json:"count"`
	Window   int      `yaml:"window,omitempty" json:"window,omitempty"`     // Window in seconds (JSON: duration string)
	GroupBy  []string `yaml:"group_by,omitempty" json:"group_by,omitempty"` // Fields to group by
	Operator string   `yaml:"operator" json:"operator,omitempty"`           // gt, gte, lt, lte, eq
}

// SequenceConfig defines sequence-based correlation settings.
type SequenceConfig struct {
	Ordered bool            `yaml:"ordered" json:"ordered"`
	MaxSpan time.Duration   `yaml:"max_span" json:"max_span,omitempty"` // JSON: duration string
	Steps   []SequenceStep  `yaml:"steps" json:"steps"`
	Events  []SequenceEvent `yaml:"events,omitempty" json:"events,omitempty"`     // Alternative to Steps
	Window  int             `yaml:"window,omitempty" json:"window,omitempty"`     // Window in seconds (JSON: duration string)
	GroupBy []string        `yaml:"group_by,omitempty" json:"group_by,omitempty"` // Fields to group by
}

// SequenceStep represents one step in a sequence.
type SequenceStep struct {
	Name       string      `yaml:"name" json:"name"`
	Conditions []Condition `yaml:"conditions" json:"conditions"`
	Required   bool        `yaml:"required" json:"required"`
}

// SequenceEvent represents an event in a sequence (alternative to SequenceStep).
type SequenceEvent struct {
	ID         string           `yaml:"id" json:"id"`
	Conditions []MatchCondition `yaml:"conditions" json:"conditions"`
}

// AggregateConfig defines aggregate-based correlation settings.
//
// The value the aggregate is compared against may be given as Value or as
// Threshold (the dashboard's name for it); Value wins when both are set.
type AggregateConfig struct {
	Function  string   `yaml:"function" json:"function"` // count, sum, avg, min, max, count_distinct
	Field     string   `yaml:"field" json:"field"`
	Operator  string   `yaml:"operator" json:"operator,omitempty"`
	Value     float64  `yaml:"value,omitempty" json:"value,omitempty"`
	Threshold float64  `yaml:"threshold,omitempty" json:"threshold"`
	Window    int      `yaml:"window,omitempty" json:"window,omitempty"` // Window in seconds (JSON: duration string)
	GroupBy   []string `yaml:"group_by,omitempty" json:"group_by,omitempty"`
}

// threshold returns the value the aggregate is compared against.
func (a *AggregateConfig) threshold() float64 {
	if a.Value != 0 {
		return a.Value
	}
	return a.Threshold
}

// AbsenceConfig defines absence-based correlation settings.
type AbsenceConfig struct {
	ExpectedConditions []Condition   `yaml:"expected_conditions" json:"expected_conditions"`
	AfterConditions    []Condition   `yaml:"after_conditions,omitempty" json:"after_conditions,omitempty"`
	Timeout            time.Duration `yaml:"timeout" json:"timeout,omitempty"` // JSON: duration string
	Window             int           `yaml:"window,omitempty" json:"window"`   // Window in seconds (JSON: duration string)
	GroupBy            []string      `yaml:"group_by,omitempty" json:"group_by,omitempty"`
}

// CorrelationConfig defines cross-event correlation settings.
type CorrelationConfig struct {
	Type             string     `yaml:"type,omitempty" json:"type,omitempty"`           // threshold, sequence, absence, etc.
	Window           string     `yaml:"window,omitempty" json:"window,omitempty"`       // Duration string like "30m"
	Threshold        int        `yaml:"threshold,omitempty" json:"threshold,omitempty"` // Threshold count
	GroupBy          []string   `yaml:"group_by,omitempty" json:"group_by,omitempty"`
	MinHits          int        `yaml:"min_hits,omitempty" json:"min_hits,omitempty"`
	AbsenceCondition *Condition `yaml:"absence_condition,omitempty" json:"absence_condition,omitempty"` // Condition that should be absent
}

// ActionConfig defines actions to take when rule fires.
type ActionConfig struct {
	Type   string         `yaml:"type" json:"type"` // alert, webhook, log, suppress
	Config map[string]any `yaml:"config,omitempty" json:"config,omitempty"`
}

// validOperators are the condition operators the engine evaluates, for both
// Conditions.Match entries and Condition trees.
var validOperators = map[string]bool{
	"eq": true, "ne": true, "gt": true, "gte": true, "lt": true, "lte": true,
	"contains": true, "prefix": true, "regex": true,
	"in": true, "not_in": true, "exists": true, "not_exists": true,
}

// validCompareOperators are the operators threshold and aggregate configs use
// to compare a count or aggregate against their threshold ("" means gte).
var validCompareOperators = map[string]bool{
	"": true, "gt": true, "gte": true, "lt": true, "lte": true, "eq": true,
	">": true, ">=": true, "<": true, "<=": true, "=": true,
}

// validAggregateFunctions are the aggregate functions the engine implements.
var validAggregateFunctions = map[string]bool{
	"count": true, "sum": true, "avg": true, "min": true, "max": true, "count_distinct": true,
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
	case RuleTypeThreshold, RuleTypeSequence, RuleTypeAggregate, RuleTypeAbsence, RuleTypeCustom:
	default:
		return fmt.Errorf("unknown rule type: %s", r.Type)
	}
	if r.Severity < MinRuleSeverity || r.Severity > MaxRuleSeverity {
		return fmt.Errorf("severity must be between %d and %d, got %d", MinRuleSeverity, MaxRuleSeverity, r.Severity)
	}

	switch r.Type {
	case RuleTypeThreshold:
		if r.Threshold == nil {
			return fmt.Errorf("threshold config required for threshold rules")
		}
		if r.Threshold.Count <= 0 {
			return fmt.Errorf("threshold count must be positive")
		}
		if !validCompareOperators[r.Threshold.Operator] {
			return fmt.Errorf("threshold: invalid operator: %s", r.Threshold.Operator)
		}
		if !r.hasFilter() {
			return fmt.Errorf("threshold rules require at least one condition (conditions.match, event_conditions or condition)")
		}
	case RuleTypeSequence:
		if r.Sequence == nil {
			return fmt.Errorf("sequence config required for sequence rules")
		}
		if len(r.Sequence.Steps) < 2 {
			return fmt.Errorf("sequence rules require at least 2 steps")
		}
		for i, step := range r.Sequence.Steps {
			if len(step.Conditions) == 0 {
				return fmt.Errorf("sequence step %d (%s): at least one condition is required", i, step.Name)
			}
			if err := validateConditions(step.Conditions); err != nil {
				return fmt.Errorf("sequence step %d (%s): %w", i, step.Name, err)
			}
		}
		if r.Sequence.MaxSpan < 0 {
			return fmt.Errorf("sequence max_span must not be negative")
		}
	case RuleTypeAggregate:
		if r.Aggregate == nil {
			return fmt.Errorf("aggregate config required for aggregate rules")
		}
		if err := r.Aggregate.validate(); err != nil {
			return fmt.Errorf("aggregate: %w", err)
		}
		if !r.hasFilter() {
			return fmt.Errorf("aggregate rules require at least one condition (conditions.match, event_conditions or condition)")
		}
	case RuleTypeAbsence:
		if r.Absence == nil {
			return fmt.Errorf("absence config required for absence rules")
		}
		if len(r.Absence.ExpectedConditions) == 0 {
			return fmt.Errorf("absence rules require at least one expected_condition")
		}
		for i, cond := range r.Absence.ExpectedConditions {
			if cond.Field == "" {
				return fmt.Errorf("absence expected_condition %d: field is required", i)
			}
			if err := cond.Validate(); err != nil {
				return fmt.Errorf("absence expected_condition %d: %w", i, err)
			}
		}
		if err := validateConditions(r.Absence.AfterConditions); err != nil {
			return fmt.Errorf("absence after_conditions: %w", err)
		}
	case RuleTypeCustom:
		// Custom rules have no specific requirements
	default:
		return fmt.Errorf("unknown rule type: %s", r.Type)
	}

	if r.Type != RuleTypeCustom && r.Window <= 0 {
		return fmt.Errorf("window must be a positive duration (e.g. 5m)")
	}

	// Validate match conditions
	for i, cond := range r.Conditions.Match {
		if cond.Field == "" {
			return fmt.Errorf("match condition %d: field is required", i)
		}
		if cond.Operator == "" {
			return fmt.Errorf("match condition %d: operator is required", i)
		}
		if err := validateOperand(cond.Operator, cond.Value, nil); err != nil {
			return fmt.Errorf("match condition %d (%s): %w", i, cond.Field, err)
		}
	}
	if err := validateConditions(r.EventConditions); err != nil {
		return fmt.Errorf("event_conditions: %w", err)
	}
	if !r.Condition.IsZero() {
		if err := r.Condition.Validate(); err != nil {
			return fmt.Errorf("condition: %w", err)
		}
	}

	seen := make(map[string]bool, len(r.DependsOn))
	for _, dep := range r.DependsOn {
		switch {
		case dep == "":
			return fmt.Errorf("depends_on: empty rule ID")
		case dep == r.ID:
			return fmt.Errorf("depends_on: rule cannot depend on itself")
		case seen[dep]:
			return fmt.Errorf("depends_on: duplicate rule ID %q", dep)
		}
		seen[dep] = true
	}

	return nil
}

// hasFilter reports whether the rule restricts which events it evaluates.
func (r *Rule) hasFilter() bool {
	return len(r.Conditions.Match) > 0 || len(r.EventConditions) > 0 || !r.Condition.IsZero()
}

func (a *AggregateConfig) validate() error {
	if !validAggregateFunctions[a.Function] {
		return fmt.Errorf("unknown function: %q", a.Function)
	}
	if a.Function != "count" && a.Field == "" {
		return fmt.Errorf("field is required for function %s", a.Function)
	}
	if !validCompareOperators[a.Operator] {
		return fmt.Errorf("invalid operator: %s", a.Operator)
	}
	if a.Value != 0 && a.Threshold != 0 && a.Value != a.Threshold {
		return fmt.Errorf("value (%v) and threshold (%v) disagree; set only one", a.Value, a.Threshold)
	}
	return nil
}

func validateConditions(conds []Condition) error {
	for i := range conds {
		if err := conds[i].Validate(); err != nil {
			return fmt.Errorf("condition %d: %w", i, err)
		}
	}
	return nil
}

// Validate validates a condition and, recursively, its And/Or children.
func (c *Condition) Validate() error {
	if c.Field == "" {
		if len(c.And) == 0 && len(c.Or) == 0 {
			return fmt.Errorf("field is required")
		}
		if c.Operator != "" {
			return fmt.Errorf("operator %q requires a field", c.Operator)
		}
	} else {
		if c.Operator == "" {
			return fmt.Errorf("operator is required")
		}
		if err := validateOperand(c.Operator, c.Value, c.Values); err != nil {
			return fmt.Errorf("field %s: %w", c.Field, err)
		}
	}
	for i := range c.And {
		if err := c.And[i].Validate(); err != nil {
			return fmt.Errorf("and[%d]: %w", i, err)
		}
	}
	for i := range c.Or {
		if err := c.Or[i].Validate(); err != nil {
			return fmt.Errorf("or[%d]: %w", i, err)
		}
	}
	return nil
}

// validateOperand checks that operator is known and that value/values carry
// what the operator needs.
func validateOperand(operator string, value any, values []string) error {
	if !validOperators[operator] {
		return fmt.Errorf("invalid operator: %s", operator)
	}
	switch operator {
	case "exists", "not_exists":
		return nil
	case "in", "not_in":
		if len(values) == 0 && len(listValues(value)) == 0 {
			return fmt.Errorf("values required for %s operator", operator)
		}
		return nil
	case "regex":
		pattern := fmt.Sprintf("%v", value)
		if value == nil || pattern == "" {
			return fmt.Errorf("regex operator requires a pattern value")
		}
		if _, err := compileRegex(pattern); err != nil {
			return fmt.Errorf("invalid regex %q: %w", pattern, err)
		}
		return nil
	}
	if value == nil {
		return fmt.Errorf("value required for %s operator", operator)
	}
	return nil
}

// listValues returns the elements of a list-valued condition value as
// strings, or nil if value is not a list.
func listValues(value any) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, len(v))
		for i, item := range v {
			out[i] = fmt.Sprintf("%v", item)
		}
		return out
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
		cmp, ok := c.matchCompare(eventValue)
		return ok && cmp > 0
	case "gte":
		cmp, ok := c.matchCompare(eventValue)
		return ok && cmp >= 0
	case "lt":
		cmp, ok := c.matchCompare(eventValue)
		return ok && cmp < 0
	case "lte":
		cmp, ok := c.matchCompare(eventValue)
		return ok && cmp <= 0
	case "contains":
		return c.matchContains(eventValue)
	case "prefix":
		return strings.HasPrefix(fmt.Sprintf("%v", eventValue), fmt.Sprintf("%v", c.Value))
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

// matchCompare compares eventValue with the condition value: numerically when
// both are numbers, as strings when neither is. A missing field (nil) or a
// number compared with a non-number is not comparable (ok is false), so it
// satisfies none of gt/gte/lt/lte; otherwise "<nil>" or "abc" would compare
// above every number and an event lacking the field would pass e.g.
// "value_eth gte 1000".
func (c *Condition) matchCompare(eventValue any) (cmp int, ok bool) {
	if eventValue == nil || c.Value == nil {
		return 0, false
	}
	numVal, ok1 := toFloat64(eventValue)
	condVal, ok2 := toFloat64(c.Value)
	switch {
	case ok1 && ok2:
		switch {
		case numVal < condVal:
			return -1, true
		case numVal > condVal:
			return 1, true
		}
		return 0, true
	case !ok1 && !ok2:
		return strings.Compare(fmt.Sprintf("%v", eventValue), fmt.Sprintf("%v", c.Value)), true
	}
	return 0, false
}

func (c *Condition) matchContains(eventValue any) bool {
	str := fmt.Sprintf("%v", eventValue)
	pattern := fmt.Sprintf("%v", c.Value)
	return strings.Contains(strings.ToLower(str), strings.ToLower(pattern))
}

// maxRegexPatternLen limits regex pattern length to prevent resource exhaustion.
const maxRegexPatternLen = 1024

// regexCache holds compiled rule patterns. Patterns come from rule
// definitions, not from events, so the cache is bounded by the rule set.
var regexCache sync.Map // pattern -> *regexp.Regexp

func compileRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxRegexPatternLen {
		return nil, fmt.Errorf("pattern longer than %d bytes", maxRegexPatternLen)
	}
	if re, ok := regexCache.Load(pattern); ok {
		return re.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}

func (c *Condition) matchRegex(eventValue any) bool {
	re, err := compileRegex(fmt.Sprintf("%v", c.Value))
	if err != nil {
		return false
	}
	return re.MatchString(fmt.Sprintf("%v", eventValue))
}

func (c *Condition) matchIn(eventValue any) bool {
	values := c.Values
	if len(values) == 0 {
		values = listValues(c.Value)
	}
	str := fmt.Sprintf("%v", eventValue)
	for _, v := range values {
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

// yamlDocuments splits a YAML stream into the root node of each non-empty
// document.
func yamlDocuments(data []byte) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []*yaml.Node
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, err
		}
		if len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]
		if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
			continue // empty document, e.g. a trailing "---"
		}
		docs = append(docs, root)
	}
}

// ParseRule parses a single rule from YAML bytes. The input must hold exactly
// one YAML document; use ParseRules for files with several rules.
func ParseRule(data []byte) (*Rule, error) {
	docs, err := yamlDocuments(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rule: %w", err)
	}
	if len(docs) != 1 {
		return nil, fmt.Errorf("failed to parse rule: expected exactly one YAML document, found %d", len(docs))
	}
	if docs[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("failed to parse rule: expected a rule mapping")
	}
	var rule Rule
	if err := docs[0].Decode(&rule); err != nil {
		return nil, fmt.Errorf("failed to parse rule: %w", err)
	}
	if err := rule.Validate(); err != nil {
		return nil, fmt.Errorf("invalid rule: %w", err)
	}
	return &rule, nil
}

// ParseRules parses one or more rules from YAML bytes. Each document of the
// stream may hold a single rule mapping or a list of rules. Every rule is
// validated, and rule IDs must be unique within the input; all problems are
// reported together.
func ParseRules(data []byte) ([]*Rule, error) {
	docs, err := yamlDocuments(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rules: %w", err)
	}

	var rules []*Rule
	var errs []error
	for i, doc := range docs {
		switch doc.Kind {
		case yaml.MappingNode:
			var rule Rule
			if err := doc.Decode(&rule); err != nil {
				errs = append(errs, fmt.Errorf("document %d: %w", i+1, err))
				continue
			}
			rules = append(rules, &rule)
		case yaml.SequenceNode:
			var list []*Rule
			if err := doc.Decode(&list); err != nil {
				errs = append(errs, fmt.Errorf("document %d: %w", i+1, err))
				continue
			}
			rules = append(rules, list...)
		default:
			errs = append(errs, fmt.Errorf("document %d: expected a rule mapping or a list of rules", i+1))
		}
	}
	if len(rules) == 0 && len(errs) == 0 {
		return nil, fmt.Errorf("no rules found")
	}

	seen := make(map[string]bool, len(rules))
	for i, rule := range rules {
		if rule == nil {
			errs = append(errs, fmt.Errorf("rule %d: empty rule", i))
			continue
		}
		if err := rule.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("rule %d (%s): %w", i, rule.ID, err))
			continue
		}
		if seen[rule.ID] {
			errs = append(errs, fmt.Errorf("rule %d: duplicate rule ID %q", i, rule.ID))
		}
		seen[rule.ID] = true
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return rules, nil
}

// ruleIDFields are the fields of a re-injected alert.fired event that name the
// rule which fired (see AlertReinjector).
var ruleIDFields = map[string]bool{"metadata.rule_id": true, "rule_id": true}

// ReferencedRuleIDs returns the IDs of the rules this rule builds on: its
// depends_on entries and every rule ID its conditions wait for in re-injected
// alert.fired events (eq or in on metadata.rule_id). The result is ordered and
// free of duplicates.
func (r *Rule) ReferencedRuleIDs() []string {
	var ids []string
	seen := make(map[string]bool)
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, dep := range r.DependsOn {
		add(dep)
	}
	r.walkConditions(func(field, operator string, value any, values []string) {
		if !ruleIDFields[field] {
			return
		}
		switch operator {
		case "eq":
			if id, ok := value.(string); ok {
				add(id)
			}
		case "in":
			for _, id := range values {
				add(id)
			}
			for _, id := range listValues(value) {
				add(id)
			}
		}
	})
	return ids
}

// isAlertField reports whether field names metadata that only the alert.fired
// events built by AlertReinjector carry (with or without the "metadata."
// prefix, as getEventField accepts both).
func isAlertField(field string) bool {
	switch key := strings.TrimPrefix(field, "metadata."); key {
	case "alert_id", "rule_id", "rule_name", "group_key", "event_count",
		metaIsSynthetic, metaChainDepth, "mitre_tactic", "mitre_technique":
		return true
	default:
		return strings.HasPrefix(key, "tag_")
	}
}

// consumesAlerts reports whether the rule is written to evaluate the
// synthetic alert.fired events that AlertReinjector feeds back into the
// engine: it depends on other rules or one of its conditions tests the action
// against an alert action or tests alert metadata.
func (r *Rule) consumesAlerts() bool {
	if len(r.DependsOn) > 0 {
		return true
	}
	consumes := false
	r.walkConditions(func(field, _ string, value any, values []string) {
		switch {
		case consumes:
		case isAlertField(field):
			consumes = true
		case field == "action":
			candidates := append([]string{fmt.Sprintf("%v", value)}, values...)
			candidates = append(candidates, listValues(value)...)
			for _, v := range candidates {
				if strings.Contains(strings.ToLower(v), "alert") {
					consumes = true
					return
				}
			}
		}
	})
	return consumes
}

// walkConditions calls fn for every leaf condition of the rule: filters,
// sequence steps and absence conditions.
func (r *Rule) walkConditions(fn func(field, operator string, value any, values []string)) {
	var walk func(c Condition)
	walk = func(c Condition) {
		if c.Field != "" {
			fn(c.Field, c.Operator, c.Value, c.Values)
		}
		for _, sub := range c.And {
			walk(sub)
		}
		for _, sub := range c.Or {
			walk(sub)
		}
	}
	walkAll := func(conds []Condition) {
		for _, c := range conds {
			walk(c)
		}
	}

	for _, m := range r.Conditions.Match {
		fn(m.Field, m.Operator, m.Value, nil)
	}
	walkAll(r.EventConditions)
	walk(r.Condition)
	if r.Sequence != nil {
		for _, step := range r.Sequence.Steps {
			walkAll(step.Conditions)
		}
		for _, ev := range r.Sequence.Events {
			for _, m := range ev.Conditions {
				fn(m.Field, m.Operator, m.Value, nil)
			}
		}
	}
	if r.Absence != nil {
		walkAll(r.Absence.ExpectedConditions)
		walkAll(r.Absence.AfterConditions)
	}
}

// ValidateDependencies checks that every rule each rule builds on (see
// ReferencedRuleIDs) is either one of rules or listed in known. It returns
// one joined error naming every unresolved reference, or nil.
func ValidateDependencies(rules []*Rule, known map[string]bool) error {
	ids := make(map[string]bool, len(rules)+len(known))
	for id, ok := range known {
		if ok {
			ids[id] = true
		}
	}
	for _, r := range rules {
		ids[r.ID] = true
	}
	var errs []error
	for _, r := range rules {
		for _, ref := range r.ReferencedRuleIDs() {
			if !ids[ref] {
				errs = append(errs, fmt.Errorf("rule %s: depends on unknown rule %q", r.ID, ref))
			}
		}
	}
	return errors.Join(errs...)
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

// IntToSeverity converts numeric severity to Severity type.
func IntToSeverity(i int) Severity {
	switch {
	case i <= 2:
		return SeverityLow
	case i <= 5:
		return SeverityMedium
	case i <= 8:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}
