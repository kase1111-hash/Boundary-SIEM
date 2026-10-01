package correlation

import (
	"strings"
	"testing"
	"time"
)

func validThresholdRule() Rule {
	return Rule{
		ID:       "v-1",
		Name:     "valid",
		Type:     RuleTypeThreshold,
		Enabled:  true,
		Severity: 5,
		Window:   time.Minute,
		Conditions: Conditions{Match: []MatchCondition{
			{Field: "action", Operator: "eq", Value: "auth.failure"},
		}},
		Threshold: &ThresholdConfig{Count: 3, Operator: "gte"},
	}
}

// Regression (R22): Validate accepted unknown operators, out-of-range
// severities, rules without any conditions or window, and self dependencies.
func TestRule_ValidateRejectsInvalidRules(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(r *Rule)
		wantErr string // substring; empty = valid
	}{
		{name: "baseline valid rule", mutate: func(r *Rule) {}},
		{
			name:    "unknown match operator",
			mutate:  func(r *Rule) { r.Conditions.Match[0].Operator = "equalz" },
			wantErr: "operator",
		},
		{
			name: "unknown event_conditions operator",
			mutate: func(r *Rule) {
				r.EventConditions = []Condition{{Field: "action", Operator: "equalz", Value: "x"}}
			},
			wantErr: "operator",
		},
		{
			name: "unknown operator nested in condition tree",
			mutate: func(r *Rule) {
				r.Condition = Condition{Or: []Condition{{Field: "a", Operator: "nope", Value: 1}}}
			},
			wantErr: "operator",
		},
		{name: "severity 0", mutate: func(r *Rule) { r.Severity = 0 }, wantErr: "severity"},
		{name: "severity 99", mutate: func(r *Rule) { r.Severity = 99 }, wantErr: "severity"},
		{name: "severity 1", mutate: func(r *Rule) { r.Severity = 1 }},
		{name: "severity 10", mutate: func(r *Rule) { r.Severity = 10 }},
		{
			name:    "threshold rule without conditions",
			mutate:  func(r *Rule) { r.Conditions = Conditions{} },
			wantErr: "condition",
		},
		{
			name: "threshold rule filtered by event_conditions only",
			mutate: func(r *Rule) {
				r.Conditions = Conditions{}
				r.EventConditions = []Condition{{Field: "action", Operator: "eq", Value: "x"}}
			},
		},
		{name: "missing window", mutate: func(r *Rule) { r.Window = 0 }, wantErr: "window"},
		{name: "unknown threshold operator", mutate: func(r *Rule) { r.Threshold.Operator = "about" }, wantErr: "operator"},
		{
			name:    "in operator without values",
			mutate:  func(r *Rule) { r.EventConditions = []Condition{{Field: "action", Operator: "in"}} },
			wantErr: "values",
		},
		{
			name: "in operator with value list",
			mutate: func(r *Rule) {
				r.Conditions.Match[0] = MatchCondition{Field: "action", Operator: "in", Value: []any{"a", "b"}}
			},
		},
		{
			name:    "invalid regex",
			mutate:  func(r *Rule) { r.Conditions.Match[0] = MatchCondition{Field: "action", Operator: "regex", Value: "("} },
			wantErr: "regex",
		},
		{name: "depends on itself", mutate: func(r *Rule) { r.DependsOn = []string{"v-1"} }, wantErr: "depends_on"},
		{name: "empty depends_on entry", mutate: func(r *Rule) { r.DependsOn = []string{""} }, wantErr: "depends_on"},
		{
			name: "aggregate with unknown function",
			mutate: func(r *Rule) {
				r.Type = RuleTypeAggregate
				r.Threshold = nil
				r.Aggregate = &AggregateConfig{Function: "median", Field: "x", Operator: "gte", Value: 1}
			},
			wantErr: "function",
		},
		{
			name: "aggregate value and threshold disagree",
			mutate: func(r *Rule) {
				r.Type = RuleTypeAggregate
				r.Threshold = nil
				r.Aggregate = &AggregateConfig{Function: "sum", Field: "x", Value: 1, Threshold: 2}
			},
			wantErr: "threshold",
		},
		{
			name: "sequence step without conditions",
			mutate: func(r *Rule) {
				r.Type = RuleTypeSequence
				r.Threshold = nil
				r.Sequence = &SequenceConfig{Steps: []SequenceStep{
					{Name: "a", Conditions: []Condition{{Field: "action", Operator: "eq", Value: "a"}}},
					{Name: "b"},
				}}
			},
			wantErr: "step",
		},
		{
			name: "absence expected condition with bad operator",
			mutate: func(r *Rule) {
				r.Type = RuleTypeAbsence
				r.Threshold = nil
				r.Absence = &AbsenceConfig{ExpectedConditions: []Condition{{Field: "action", Operator: "equalz", Value: "x"}}}
			},
			wantErr: "operator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validThresholdRule()
			tt.mutate(&r)
			err := r.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("Validate() = %v, want nil", err)
			case tt.wantErr != "" && err == nil:
				t.Errorf("Validate() = nil, want error containing %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(strings.ToLower(err.Error()), tt.wantErr):
				t.Errorf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

const twoRuleStream = `---
id: multi-1
name: m1
type: threshold
severity: 5
window: 1m
conditions:
  match:
    - {field: action, operator: eq, value: a.a}
threshold: {count: 1}
---
id: multi-2
name: m2
type: threshold
severity: 5
window: 1m
conditions:
  match:
    - {field: action, operator: eq, value: b.b}
threshold: {count: 1}
`

// Regression (R22): multi-document YAML silently dropped every rule after the
// first, and unknown rule types produced a confusing unmarshal error.
func TestParseRules_Documents(t *testing.T) {
	rules, err := ParseRules([]byte(twoRuleStream))
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if len(rules) != 2 || rules[0].ID != "multi-1" || rules[1].ID != "multi-2" {
		t.Fatalf("ParseRules returned %d rule(s), want multi-1 and multi-2", len(rules))
	}

	if _, err := ParseRule([]byte(twoRuleStream)); err == nil {
		t.Error("ParseRule accepted a two-document stream; it must not silently drop the second rule")
	}

	_, err = ParseRules([]byte("id: bad-type\nname: x\ntype: nonsense\nwindow: 5m\n"))
	if err == nil || !strings.Contains(err.Error(), "unknown rule type") {
		t.Errorf("ParseRules(bad type) error = %v, want 'unknown rule type'", err)
	}
}
