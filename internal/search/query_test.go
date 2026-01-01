package search

import (
	"testing"
)

func TestLexer_NextToken(t *testing.T) {
	tests := []struct {
		input    string
		expected []Token
	}{
		{
			input: "action:auth.failure",
			expected: []Token{
				{Type: TokenField, Value: "action"},
				{Type: TokenOperator, Value: "="},
				{Type: TokenValue, Value: "auth.failure"},
				{Type: TokenEOF},
			},
		},
		{
			input: "severity>5",
			expected: []Token{
				{Type: TokenField, Value: "severity"},
				{Type: TokenOperator, Value: ">"},
				{Type: TokenValue, Value: "5"},
				{Type: TokenEOF},
			},
		},
		{
			input: "severity>=7",
			expected: []Token{
				{Type: TokenField, Value: "severity"},
				{Type: TokenOperator, Value: ">="},
				{Type: TokenValue, Value: "7"},
				{Type: TokenEOF},
			},
		},
		{
			input: `action:"login failed"`,
			expected: []Token{
				{Type: TokenField, Value: "action"},
				{Type: TokenOperator, Value: "="},
				{Type: TokenValue, Value: "login failed"},
				{Type: TokenEOF},
			},
		},
		{
			input: "action:auth.* AND severity>5",
			expected: []Token{
				{Type: TokenField, Value: "action"},
				{Type: TokenOperator, Value: "="},
				{Type: TokenValue, Value: "auth.*"},
				{Type: TokenAnd, Value: "AND"},
				{Type: TokenField, Value: "severity"},
				{Type: TokenOperator, Value: ">"},
				{Type: TokenValue, Value: "5"},
				{Type: TokenEOF},
			},
		},
		{
			input: "action:login OR action:logout",
			expected: []Token{
				{Type: TokenField, Value: "action"},
				{Type: TokenOperator, Value: "="},
				{Type: TokenValue, Value: "login"},
				{Type: TokenOr, Value: "OR"},
				{Type: TokenField, Value: "action"},
				{Type: TokenOperator, Value: "="},
				{Type: TokenValue, Value: "logout"},
				{Type: TokenEOF},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			lexer := NewLexer(tt.input)
			for i, expected := range tt.expected {
				token := lexer.NextToken()
				if token.Type != expected.Type {
					t.Errorf("token %d: got type %v, want %v", i, token.Type, expected.Type)
				}
				if token.Value != expected.Value {
					t.Errorf("token %d: got value %q, want %q", i, token.Value, expected.Value)
				}
			}
		})
	}
}

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantConditions int
		wantError      bool
	}{
		{
			name:           "simple equality",
			input:          "action:auth.failure",
			wantConditions: 1,
		},
		{
			name:           "comparison operator",
			input:          "severity>5",
			wantConditions: 1,
		},
		{
			name:           "AND condition",
			input:          "action:auth.failure AND severity:>5",
			wantConditions: 2,
		},
		{
			name:           "OR condition",
			input:          "action:login OR action:logout",
			wantConditions: 2,
		},
		{
			name:           "complex query",
			input:          "action:auth.* AND severity:>=7 AND outcome:failure",
			wantConditions: 3,
		},
		{
			name:           "empty query",
			input:          "",
			wantConditions: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, err := ParseQuery(tt.input)
			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(query.Conditions) != tt.wantConditions {
				t.Errorf("got %d conditions, want %d", len(query.Conditions), tt.wantConditions)
			}
		})
	}
}

func TestParser_ParseCondition(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		field    string
		operator Operator
		value    interface{}
		isRegex  bool
	}{
		{
			name:     "equality",
			input:    "action:auth.failure",
			field:    "action",
			operator: OpEquals,
			value:    "auth.failure",
		},
		{
			name:     "greater than",
			input:    "severity>5",
			field:    "severity",
			operator: OpGreater,
			value:    int64(5),
		},
		{
			name:     "greater or equal",
			input:    "severity>=7",
			field:    "severity",
			operator: OpGreaterEq,
			value:    int64(7),
		},
		{
			name:     "less than",
			input:    "severity<3",
			field:    "severity",
			operator: OpLess,
			value:    int64(3),
		},
		{
			name:     "not equals",
			input:    "outcome!=success",
			field:    "outcome",
			operator: OpNotEquals,
			value:    "success",
		},
		{
			name:     "wildcard",
			input:    "action:auth.*",
			field:    "action",
			operator: OpEquals,
			value:    "^auth\\..*$",
			isRegex:  true,
		},
		{
			name:     "contains",
			input:    "raw~error",
			field:    "raw",
			operator: OpContains,
			value:    "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, err := ParseQuery(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(query.Conditions) != 1 {
				t.Fatalf("expected 1 condition, got %d", len(query.Conditions))
			}

			cond := query.Conditions[0]
			if cond.Field != tt.field {
				t.Errorf("field: got %q, want %q", cond.Field, tt.field)
			}
			if cond.Operator != tt.operator {
				t.Errorf("operator: got %q, want %q", cond.Operator, tt.operator)
			}
			if cond.Value != tt.value {
				t.Errorf("value: got %v (%T), want %v (%T)", cond.Value, cond.Value, tt.value, tt.value)
			}
			if cond.IsRegex != tt.isRegex {
				t.Errorf("isRegex: got %v, want %v", cond.IsRegex, tt.isRegex)
			}
		})
	}
}

func TestMapField(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		found    bool
	}{
		{"action", "action", true},
		{"severity", "severity", true},
		{"user", "actor_name", true},
		{"username", "actor_name", true},
		{"src", "actor_ip", true},
		{"source.product", "source_product", true},
		{"actor.name", "actor_name", true},
		{"unknown_field", "unknown_field", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, found := MapField(tt.input)
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
			if found != tt.found {
				t.Errorf("found: got %v, want %v", found, tt.found)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"now", true},
		{"now-1h", true},
		{"now-24h", true},
		{"now-7d", true},
		{"now+1h", true},
		{"1h", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, ok := parseDuration(tt.input)
			if ok != tt.expected {
				t.Errorf("got %v, want %v", ok, tt.expected)
			}
		})
	}
}

func TestQuery_String(t *testing.T) {
	query := &Query{
		Conditions: []Condition{
			{Field: "action", Operator: OpEquals, Value: "auth.failure"},
			{Field: "severity", Operator: OpGreater, Value: 5},
		},
		Logic: []string{"AND"},
	}

	result := query.String()
	expected := "action=auth.failure AND severity>5"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func BenchmarkParser_Parse(b *testing.B) {
	input := "action:auth.* AND severity:>=7 AND outcome:failure AND source.product:boundary-daemon"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseQuery(input)
	}
}

func BenchmarkLexer_NextToken(b *testing.B) {
	input := "action:auth.failure AND severity:>5 AND outcome:failure"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lexer := NewLexer(input)
		for {
			token := lexer.NextToken()
			if token.Type == TokenEOF {
				break
			}
		}
	}
}
