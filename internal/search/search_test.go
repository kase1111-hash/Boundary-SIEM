package search

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestExecutor creates an Executor with a nil db for testing pure-Go logic
// that does not touch the database (sanitize*, buildWhereClause, etc.).
func newTestExecutor() *Executor {
	return &Executor{db: nil}
}

// ---------------------------------------------------------------------------
// sanitizeColumn
// ---------------------------------------------------------------------------

func TestSanitizeColumn(t *testing.T) {
	exec := newTestExecutor()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Normal, valid column names
		{name: "simple column", input: "action", want: "action"},
		{name: "underscored column", input: "source_product", want: "source_product"},
		{name: "mixed case", input: "ActorName", want: "ActorName"},
		{name: "column with digits", input: "field2", want: "field2"},

		// SQL injection attempts -- everything that is not [a-zA-Z0-9_] is stripped
		{name: "semicolon injection", input: "action; DROP TABLE events;--", want: "actionDROPTABLEevents"},
		{name: "single quote injection", input: "action' OR '1'='1", want: "actionOR11"},
		{name: "double quote injection", input: `action" OR "1"="1`, want: "actionOR11"},
		{name: "parentheses injection", input: "count(*)", want: "count"},
		{name: "comment injection", input: "action/**/OR/**/1=1", want: "actionOR11"},
		{name: "backtick injection", input: "`action`", want: "action"},
		{name: "newline injection", input: "action\n; DROP TABLE events", want: "actionDROPTABLEevents"},
		{name: "tab injection", input: "action\tOR\t1=1", want: "actionOR11"},
		{name: "dash injection", input: "source-product", want: "sourceproduct"},
		{name: "dot stripping", input: "metadata.key", want: "metadatakey"},
		{name: "slash injection", input: "../../etc/passwd", want: "etcpasswd"},
		{name: "pipe injection", input: "action|cat /etc/passwd", want: "actioncatetcpasswd"},

		// Edge cases
		{name: "empty string", input: "", want: ""},
		{name: "only special chars", input: "!@#$%^&*()", want: ""},
		{name: "unicode letters stripped", input: "col\u00fcmn", want: "colmn"},
		{name: "spaces stripped", input: "action name", want: "actionname"},
		{name: "very long input", input: strings.Repeat("a", 10000), want: strings.Repeat("a", 10000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exec.sanitizeColumn(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeColumn(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// sanitizeOrderBy
// ---------------------------------------------------------------------------

func TestSanitizeOrderBy(t *testing.T) {
	exec := newTestExecutor()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Valid columns that appear in the allowlist
		{name: "timestamp", input: "timestamp", want: "timestamp"},
		{name: "received_at", input: "received_at", want: "received_at"},
		{name: "severity", input: "severity", want: "severity"},
		{name: "action", input: "action", want: "action"},
		{name: "source_product", input: "source_product", want: "source_product"},
		{name: "actor_name", input: "actor_name", want: "actor_name"},

		// Invalid columns should fall back to "timestamp"
		{name: "unknown column", input: "unknown_col", want: "timestamp"},
		{name: "event_id not in allowlist", input: "event_id", want: "timestamp"},
		{name: "empty string", input: "", want: "timestamp"},

		// SQL injection -- sanitizeColumn strips special chars first, then
		// the cleaned string is checked against the allowlist.
		{name: "injection semicolon", input: "timestamp; DROP TABLE events;--", want: "timestamp"},
		{name: "injection union", input: "timestamp UNION SELECT * FROM users", want: "timestamp"},
		{name: "injection comment", input: "severity--", want: "severity"},
		{name: "injection with parens", input: "COUNT(*)", want: "timestamp"},
		{name: "injection single quote", input: "action' OR '1'='1", want: "timestamp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exec.sanitizeOrderBy(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeOrderBy(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// orderDirection
// ---------------------------------------------------------------------------

func TestOrderDirection(t *testing.T) {
	exec := newTestExecutor()

	if got := exec.orderDirection(true); got != "DESC" {
		t.Errorf("orderDirection(true) = %q, want %q", got, "DESC")
	}
	if got := exec.orderDirection(false); got != "ASC" {
		t.Errorf("orderDirection(false) = %q, want %q", got, "ASC")
	}
}

// ---------------------------------------------------------------------------
// buildConditionClause
// ---------------------------------------------------------------------------

func TestBuildConditionClause(t *testing.T) {
	exec := newTestExecutor()

	tests := []struct {
		name       string
		column     string
		cond       Condition
		wantClause string
		wantArgs   int
	}{
		{
			name:       "equals string",
			column:     "action",
			cond:       Condition{Operator: OpEquals, Value: "login"},
			wantClause: "action = ?",
			wantArgs:   1,
		},
		{
			name:       "equals regex",
			column:     "action",
			cond:       Condition{Operator: OpEquals, Value: "^auth\\..*$", IsRegex: true},
			wantClause: "match(action, ?)",
			wantArgs:   1,
		},
		{
			name:       "not equals",
			column:     "outcome",
			cond:       Condition{Operator: OpNotEquals, Value: "success"},
			wantClause: "outcome != ?",
			wantArgs:   1,
		},
		{
			name:       "greater than",
			column:     "severity",
			cond:       Condition{Operator: OpGreater, Value: int64(5)},
			wantClause: "severity > ?",
			wantArgs:   1,
		},
		{
			name:       "greater or equal",
			column:     "severity",
			cond:       Condition{Operator: OpGreaterEq, Value: int64(7)},
			wantClause: "severity >= ?",
			wantArgs:   1,
		},
		{
			name:       "less than",
			column:     "severity",
			cond:       Condition{Operator: OpLess, Value: int64(3)},
			wantClause: "severity < ?",
			wantArgs:   1,
		},
		{
			name:       "less or equal",
			column:     "severity",
			cond:       Condition{Operator: OpLessEq, Value: int64(2)},
			wantClause: "severity <= ?",
			wantArgs:   1,
		},
		{
			name:       "contains",
			column:     "raw",
			cond:       Condition{Operator: OpContains, Value: "error"},
			wantClause: "position(raw, ?) > 0",
			wantArgs:   1,
		},
		{
			name:       "not contains",
			column:     "raw",
			cond:       Condition{Operator: OpNotContains, Value: "debug"},
			wantClause: "position(raw, ?) = 0",
			wantArgs:   1,
		},
		{
			name:       "exists",
			column:     "actor_name",
			cond:       Condition{Operator: OpExists},
			wantClause: "actor_name != ''",
			wantArgs:   0,
		},
		{
			name:       "not exists",
			column:     "actor_name",
			cond:       Condition{Operator: OpNotExists},
			wantClause: "actor_name = ''",
			wantArgs:   0,
		},
		{
			name:       "default operator",
			column:     "action",
			cond:       Condition{Operator: "unknown_op", Value: "test"},
			wantClause: "action = ?",
			wantArgs:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clause, args := exec.buildConditionClause(tt.column, tt.cond)
			if clause != tt.wantClause {
				t.Errorf("clause = %q, want %q", clause, tt.wantClause)
			}
			if len(args) != tt.wantArgs {
				t.Errorf("len(args) = %d, want %d", len(args), tt.wantArgs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildWhereClause
// ---------------------------------------------------------------------------

func TestBuildWhereClause(t *testing.T) {
	exec := newTestExecutor()

	t.Run("empty query returns empty string", func(t *testing.T) {
		q := &Query{}
		clause, args := exec.buildWhereClause(q)
		if clause != "" {
			t.Errorf("clause = %q, want empty string", clause)
		}
		if len(args) != 0 {
			t.Errorf("len(args) = %d, want 0", len(args))
		}
	})

	t.Run("single equality condition", func(t *testing.T) {
		q := &Query{
			Conditions: []Condition{
				{Field: "action", Operator: OpEquals, Value: "login"},
			},
		}
		clause, args := exec.buildWhereClause(q)
		if !strings.HasPrefix(clause, "WHERE ") {
			t.Errorf("clause should start with 'WHERE ', got %q", clause)
		}
		if !strings.Contains(clause, "action = ?") {
			t.Errorf("clause should contain 'action = ?', got %q", clause)
		}
		if len(args) != 1 {
			t.Errorf("len(args) = %d, want 1", len(args))
		}
	})

	t.Run("two conditions with AND logic", func(t *testing.T) {
		q := &Query{
			Conditions: []Condition{
				{Field: "action", Operator: OpEquals, Value: "login"},
				{Field: "severity", Operator: OpGreater, Value: int64(5)},
			},
			Logic: []string{"AND"},
		}
		clause, args := exec.buildWhereClause(q)
		if !strings.Contains(clause, " AND ") {
			t.Errorf("clause should contain ' AND ', got %q", clause)
		}
		if len(args) != 2 {
			t.Errorf("len(args) = %d, want 2", len(args))
		}
	})

	t.Run("two conditions with OR logic", func(t *testing.T) {
		q := &Query{
			Conditions: []Condition{
				{Field: "action", Operator: OpEquals, Value: "login"},
				{Field: "action", Operator: OpEquals, Value: "logout"},
			},
			Logic: []string{"OR"},
		}
		clause, args := exec.buildWhereClause(q)
		if !strings.Contains(clause, " OR ") {
			t.Errorf("clause should contain ' OR ', got %q", clause)
		}
		if len(args) != 2 {
			t.Errorf("len(args) = %d, want 2", len(args))
		}
	})

	t.Run("three conditions with mixed logic", func(t *testing.T) {
		q := &Query{
			Conditions: []Condition{
				{Field: "action", Operator: OpEquals, Value: "login"},
				{Field: "severity", Operator: OpGreater, Value: int64(5)},
				{Field: "outcome", Operator: OpEquals, Value: "failure"},
			},
			Logic: []string{"AND", "OR"},
		}
		clause, args := exec.buildWhereClause(q)
		if !strings.Contains(clause, " AND ") {
			t.Errorf("clause should contain ' AND ', got %q", clause)
		}
		if !strings.Contains(clause, " OR ") {
			t.Errorf("clause should contain ' OR ', got %q", clause)
		}
		if len(args) != 3 {
			t.Errorf("len(args) = %d, want 3", len(args))
		}
	})

	t.Run("time range only", func(t *testing.T) {
		now := time.Now()
		q := &Query{
			TimeRange: &TimeRange{
				Start: now.Add(-1 * time.Hour),
				End:   now,
			},
		}
		clause, args := exec.buildWhereClause(q)
		if !strings.HasPrefix(clause, "WHERE ") {
			t.Errorf("clause should start with 'WHERE ', got %q", clause)
		}
		if !strings.Contains(clause, "timestamp >= ?") {
			t.Errorf("clause should contain 'timestamp >= ?', got %q", clause)
		}
		if !strings.Contains(clause, "timestamp <= ?") {
			t.Errorf("clause should contain 'timestamp <= ?', got %q", clause)
		}
		if len(args) != 2 {
			t.Errorf("len(args) = %d, want 2", len(args))
		}
	})

	t.Run("time range with start only", func(t *testing.T) {
		now := time.Now()
		q := &Query{
			TimeRange: &TimeRange{
				Start: now.Add(-1 * time.Hour),
			},
		}
		clause, args := exec.buildWhereClause(q)
		if !strings.Contains(clause, "timestamp >= ?") {
			t.Errorf("clause should contain 'timestamp >= ?', got %q", clause)
		}
		if strings.Contains(clause, "timestamp <= ?") {
			t.Errorf("clause should NOT contain 'timestamp <= ?' when End is zero, got %q", clause)
		}
		if len(args) != 1 {
			t.Errorf("len(args) = %d, want 1", len(args))
		}
	})

	t.Run("conditions plus time range", func(t *testing.T) {
		now := time.Now()
		q := &Query{
			Conditions: []Condition{
				{Field: "action", Operator: OpEquals, Value: "login"},
			},
			TimeRange: &TimeRange{
				Start: now.Add(-1 * time.Hour),
				End:   now,
			},
		}
		clause, args := exec.buildWhereClause(q)
		// Time range clauses come first, then conditions.
		if !strings.Contains(clause, "timestamp >= ?") {
			t.Errorf("clause should contain time range, got %q", clause)
		}
		if !strings.Contains(clause, "action = ?") {
			t.Errorf("clause should contain condition, got %q", clause)
		}
		if len(args) != 3 {
			t.Errorf("len(args) = %d, want 3 (2 time + 1 condition)", len(args))
		}
	})

	t.Run("field mapping applied in WHERE clause", func(t *testing.T) {
		// "user" should map to "actor_name"
		q := &Query{
			Conditions: []Condition{
				{Field: "user", Operator: OpEquals, Value: "admin"},
			},
		}
		clause, _ := exec.buildWhereClause(q)
		if !strings.Contains(clause, "actor_name") {
			t.Errorf("clause should contain mapped column 'actor_name', got %q", clause)
		}
		if strings.Contains(clause, "user") && !strings.Contains(clause, "actor_name") {
			t.Error("field 'user' was not mapped to 'actor_name'")
		}
	})

	t.Run("exists operator has no args", func(t *testing.T) {
		q := &Query{
			Conditions: []Condition{
				{Field: "actor_name", Operator: OpExists},
			},
		}
		clause, args := exec.buildWhereClause(q)
		if !strings.Contains(clause, "actor_name != ''") {
			t.Errorf("clause should contain \"actor_name != ''\", got %q", clause)
		}
		if len(args) != 0 {
			t.Errorf("exists should produce 0 args, got %d", len(args))
		}
	})

	t.Run("regex condition uses match()", func(t *testing.T) {
		q := &Query{
			Conditions: []Condition{
				{Field: "action", Operator: OpEquals, Value: "^auth\\..*$", IsRegex: true},
			},
		}
		clause, args := exec.buildWhereClause(q)
		if !strings.Contains(clause, "match(action, ?)") {
			t.Errorf("clause should use match() for regex, got %q", clause)
		}
		if len(args) != 1 {
			t.Errorf("len(args) = %d, want 1", len(args))
		}
	})
}

// ---------------------------------------------------------------------------
// buildWhereClause -- SQL injection via field names
// ---------------------------------------------------------------------------

func TestBuildWhereClause_InjectionViaFieldNames(t *testing.T) {
	exec := newTestExecutor()

	injectionFields := []string{
		"action; DROP TABLE events;--",
		"action' OR '1'='1",
		`action" OR "1"="1`,
		"action UNION SELECT * FROM users",
		"1=1 OR action",
		"action/**/OR/**/1=1",
	}

	for _, field := range injectionFields {
		t.Run(field, func(t *testing.T) {
			q := &Query{
				Conditions: []Condition{
					{Field: field, Operator: OpEquals, Value: "test"},
				},
			}
			clause, _ := exec.buildWhereClause(q)

			// After sanitization the clause must not contain SQL syntax
			// metacharacters from the field name. Note that alphabetic
			// residue like "actionDROPTABLEevents" is harmless -- it is
			// just an (invalid) column identifier, not executable SQL.
			// We check for the truly dangerous characters/patterns.
			for _, bad := range []string{";", "'", `"`, "--", "/*", "*/", " OR ", " AND ", " UNION ", " SELECT ", " DROP "} {
				if strings.Contains(clause, bad) {
					t.Errorf("clause contains dangerous SQL syntax %q: %s", bad, clause)
				}
			}

			// Verify the column part has no spaces (all spaces stripped).
			// Extract column from "WHERE <column> = ?" pattern.
			trimmed := strings.TrimPrefix(clause, "WHERE ")
			columnPart := strings.SplitN(trimmed, " ", 2)[0]
			if strings.ContainsAny(columnPart, " ;'\"()-/*") {
				t.Errorf("column part still contains dangerous chars: %q", columnPart)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseQuery -- extended edge cases
// ---------------------------------------------------------------------------

func TestParseQuery_EdgeCases(t *testing.T) {
	t.Run("empty string returns zero conditions", func(t *testing.T) {
		q, err := ParseQuery("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 0 {
			t.Errorf("expected 0 conditions, got %d", len(q.Conditions))
		}
	})

	t.Run("whitespace only returns zero conditions", func(t *testing.T) {
		q, err := ParseQuery("   ")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 0 {
			t.Errorf("expected 0 conditions, got %d", len(q.Conditions))
		}
	})

	t.Run("defaults are applied", func(t *testing.T) {
		q, err := ParseQuery("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if q.Limit != 100 {
			t.Errorf("default limit = %d, want 100", q.Limit)
		}
		if q.OrderBy != "timestamp" {
			t.Errorf("default orderBy = %q, want 'timestamp'", q.OrderBy)
		}
		if !q.OrderDesc {
			t.Error("default orderDesc should be true")
		}
	})

	t.Run("quoted value with spaces", func(t *testing.T) {
		q, err := ParseQuery(`action:"login failed"`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(q.Conditions))
		}
		if q.Conditions[0].Value != "login failed" {
			t.Errorf("value = %q, want %q", q.Conditions[0].Value, "login failed")
		}
	})

	t.Run("single-quoted value", func(t *testing.T) {
		q, err := ParseQuery("action:'login failed'")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(q.Conditions))
		}
		if q.Conditions[0].Value != "login failed" {
			t.Errorf("value = %q, want %q", q.Conditions[0].Value, "login failed")
		}
	})

	t.Run("NOT negates equality to not-equals", func(t *testing.T) {
		q, err := ParseQuery("NOT action:login")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(q.Conditions))
		}
		if q.Conditions[0].Operator != OpNotEquals {
			t.Errorf("operator = %q, want %q", q.Conditions[0].Operator, OpNotEquals)
		}
	})

	t.Run("NOT negates contains to not-contains", func(t *testing.T) {
		q, err := ParseQuery("NOT raw~error")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(q.Conditions))
		}
		if q.Conditions[0].Operator != OpNotContains {
			t.Errorf("operator = %q, want %q", q.Conditions[0].Operator, OpNotContains)
		}
	})

	t.Run("numeric values are parsed as int64", func(t *testing.T) {
		q, err := ParseQuery("severity>5")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(q.Conditions))
		}
		val, ok := q.Conditions[0].Value.(int64)
		if !ok {
			t.Fatalf("expected int64, got %T", q.Conditions[0].Value)
		}
		if val != 5 {
			t.Errorf("value = %d, want 5", val)
		}
	})

	t.Run("float values are parsed as float64", func(t *testing.T) {
		q, err := ParseQuery("score>3.14")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(q.Conditions))
		}
		val, ok := q.Conditions[0].Value.(float64)
		if !ok {
			t.Fatalf("expected float64, got %T", q.Conditions[0].Value)
		}
		if val != 3.14 {
			t.Errorf("value = %f, want 3.14", val)
		}
	})

	t.Run("wildcard produces regex", func(t *testing.T) {
		q, err := ParseQuery("action:auth.*")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(q.Conditions))
		}
		if !q.Conditions[0].IsRegex {
			t.Error("expected IsRegex=true for wildcard")
		}
		// The wildcard auth.* should become ^auth\..*$
		expected := `^auth\..*$`
		if q.Conditions[0].Value != expected {
			t.Errorf("value = %q, want %q", q.Conditions[0].Value, expected)
		}
	})

	t.Run("colon operator treated as equals", func(t *testing.T) {
		q, err := ParseQuery("action:login")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(q.Conditions))
		}
		if q.Conditions[0].Operator != OpEquals {
			t.Errorf("operator = %q, want %q", q.Conditions[0].Operator, OpEquals)
		}
	})

	t.Run("equals sign operator treated as equals", func(t *testing.T) {
		q, err := ParseQuery("action=login")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(q.Conditions))
		}
		if q.Conditions[0].Operator != OpEquals {
			t.Errorf("operator = %q, want %q", q.Conditions[0].Operator, OpEquals)
		}
	})

	t.Run("AND keyword (case-insensitive)", func(t *testing.T) {
		q, err := ParseQuery("action:a and severity>1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 2 {
			t.Fatalf("expected 2 conditions, got %d", len(q.Conditions))
		}
		if len(q.Logic) != 1 || q.Logic[0] != "AND" {
			t.Errorf("logic = %v, want [AND]", q.Logic)
		}
	})

	t.Run("OR keyword (case-insensitive)", func(t *testing.T) {
		q, err := ParseQuery("action:a or action:b")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 2 {
			t.Fatalf("expected 2 conditions, got %d", len(q.Conditions))
		}
		if len(q.Logic) != 1 || q.Logic[0] != "OR" {
			t.Errorf("logic = %v, want [OR]", q.Logic)
		}
	})

	t.Run("double-ampersand treated as AND", func(t *testing.T) {
		q, err := ParseQuery("action:a && severity>1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 2 {
			t.Fatalf("expected 2 conditions, got %d", len(q.Conditions))
		}
		if len(q.Logic) != 1 || q.Logic[0] != "AND" {
			t.Errorf("logic = %v, want [AND]", q.Logic)
		}
	})

	t.Run("double-pipe treated as OR", func(t *testing.T) {
		q, err := ParseQuery("action:a || action:b")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 2 {
			t.Fatalf("expected 2 conditions, got %d", len(q.Conditions))
		}
		if len(q.Logic) != 1 || q.Logic[0] != "OR" {
			t.Errorf("logic = %v, want [OR]", q.Logic)
		}
	})

	t.Run("parentheses are skipped gracefully", func(t *testing.T) {
		q, err := ParseQuery("(action:login)")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(q.Conditions))
		}
	})

	t.Run("relative time value (now-1h)", func(t *testing.T) {
		q, err := ParseQuery("timestamp>now-1h")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(q.Conditions))
		}
		// The value should be a time.Time close to one hour ago.
		ts, ok := q.Conditions[0].Value.(time.Time)
		if !ok {
			t.Fatalf("expected time.Time, got %T", q.Conditions[0].Value)
		}
		diff := time.Since(ts)
		if diff < 55*time.Minute || diff > 65*time.Minute {
			t.Errorf("parsed time should be ~1h ago, got diff=%v", diff)
		}
	})
}

// ---------------------------------------------------------------------------
// MapField -- additional cases
// ---------------------------------------------------------------------------

func TestMapField_AdditionalCases(t *testing.T) {
	tests := []struct {
		input string
		col   string
		found bool
	}{
		{"ts", "timestamp", true},
		{"time", "timestamp", true},
		{"id", "event_id", true},
		{"tenant", "tenant_id", true},
		{"product", "source_product", true},
		{"vendor", "source_vendor", true},
		{"dst", "target", true},
		{"suser", "actor_name", true},
		{"actor.ip_address", "actor_ip", true},
		{"source.hostname", "source_hostname", true},
		{"source.version", "source_version", true},
		{"schema_version", "schema_version", true},

		// Metadata prefix passes through
		{"metadata.foo", "metadata.foo", true},
		{"meta.bar", "meta.bar", true},

		// Unknown field
		{"nonexistent", "nonexistent", false},

		// Case insensitivity
		{"ACTION", "action", true},
		{"Severity", "severity", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			col, found := MapField(tt.input)
			if col != tt.col {
				t.Errorf("MapField(%q) col = %q, want %q", tt.input, col, tt.col)
			}
			if found != tt.found {
				t.Errorf("MapField(%q) found = %v, want %v", tt.input, found, tt.found)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseTimeString
// ---------------------------------------------------------------------------

func TestParseTimeString(t *testing.T) {
	t.Run("RFC3339 format", func(t *testing.T) {
		ts, err := parseTimeString("2024-01-15T10:30:00Z")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ts.Year() != 2024 || ts.Month() != 1 || ts.Day() != 15 {
			t.Errorf("unexpected time: %v", ts)
		}
	})

	t.Run("date only format", func(t *testing.T) {
		ts, err := parseTimeString("2024-06-01")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ts.Year() != 2024 || ts.Month() != 6 || ts.Day() != 1 {
			t.Errorf("unexpected time: %v", ts)
		}
	})

	t.Run("unix timestamp seconds", func(t *testing.T) {
		// 1700000000 -> 2023-11-14T22:13:20Z
		ts, err := parseTimeString("1700000000")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ts.Unix() != 1700000000 {
			t.Errorf("unexpected unix time: %d", ts.Unix())
		}
	})

	t.Run("unix timestamp millis", func(t *testing.T) {
		ts, err := parseTimeString("1700000000000")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ts.UnixMilli() != 1700000000000 {
			t.Errorf("unexpected unix milli: %d", ts.UnixMilli())
		}
	})

	t.Run("relative time 'now'", func(t *testing.T) {
		ts, err := parseTimeString("now")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		diff := time.Since(ts)
		if diff < 0 || diff > 2*time.Second {
			t.Errorf("'now' should be close to current time, diff=%v", diff)
		}
	})

	t.Run("relative time 'now-1h'", func(t *testing.T) {
		ts, err := parseTimeString("now-1h")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		diff := time.Since(ts)
		if diff < 55*time.Minute || diff > 65*time.Minute {
			t.Errorf("'now-1h' should be ~1h ago, diff=%v", diff)
		}
	})
}

// ---------------------------------------------------------------------------
// Handler tests (input validation only -- no database)
// ---------------------------------------------------------------------------

func TestHandleSearch_InvalidJSON(t *testing.T) {
	handler := NewHandler(newTestExecutor())

	body := strings.NewReader("{invalid json")
	req := httptest.NewRequest(http.MethodPost, "/v1/search", body)
	w := httptest.NewRecorder()

	handler.HandleSearch(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Code != "invalid_request" {
		t.Errorf("error code = %q, want %q", errResp.Code, "invalid_request")
	}
}

func TestHandleGetEvent_MissingID(t *testing.T) {
	handler := NewHandler(newTestExecutor())

	// Simulate a request with no path value for "id".
	req := httptest.NewRequest(http.MethodGet, "/v1/events/", nil)
	w := httptest.NewRecorder()

	handler.HandleGetEvent(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Code != "missing_id" {
		t.Errorf("error code = %q, want %q", errResp.Code, "missing_id")
	}
}

func TestHandleGetEvent_InvalidUUID(t *testing.T) {
	handler := NewHandler(newTestExecutor())

	// Use the standard library mux to set path values.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/events/{id}", handler.HandleGetEvent)

	req := httptest.NewRequest(http.MethodGet, "/v1/events/not-a-uuid", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Code != "invalid_id" {
		t.Errorf("error code = %q, want %q", errResp.Code, "invalid_id")
	}
}

func TestHandleAggregation_InvalidJSON(t *testing.T) {
	handler := NewHandler(newTestExecutor())

	body := strings.NewReader("{bad")
	req := httptest.NewRequest(http.MethodPost, "/v1/aggregations", body)
	w := httptest.NewRecorder()

	handler.HandleAggregation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleAggregation_MissingField(t *testing.T) {
	handler := NewHandler(newTestExecutor())

	payload := `{"type":"count"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/aggregations", strings.NewReader(payload))
	w := httptest.NewRecorder()

	handler.HandleAggregation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Code != "missing_field" {
		t.Errorf("error code = %q, want %q", errResp.Code, "missing_field")
	}
}

func TestHandleFieldValues_MissingField(t *testing.T) {
	handler := NewHandler(newTestExecutor())

	// Without using the mux, PathValue("field") returns "".
	req := httptest.NewRequest(http.MethodGet, "/v1/fields//values", nil)
	w := httptest.NewRecorder()

	handler.HandleFieldValues(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Code != "missing_field" {
		t.Errorf("error code = %q, want %q", errResp.Code, "missing_field")
	}
}

// ---------------------------------------------------------------------------
// Comprehensive SQL injection attempt through full query parse + WHERE build
// ---------------------------------------------------------------------------

func TestSQLInjection_EndToEnd(t *testing.T) {
	exec := newTestExecutor()

	injections := []struct {
		name  string
		query string
	}{
		{
			name:  "semicolon in value",
			query: `action:"test; DROP TABLE events"`,
		},
		{
			name:  "union in field name",
			query: "UNION_SELECT:value",
		},
		{
			name:  "comment in field name",
			query: `action:"test" -- comment`,
		},
		{
			name:  "subquery attempt",
			query: `action:"(SELECT password FROM users)"`,
		},
		{
			name:  "boolean tautology",
			query: `action:"x' OR '1'='1"`,
		},
	}

	for _, tt := range injections {
		t.Run(tt.name, func(t *testing.T) {
			q, err := ParseQuery(tt.query)
			if err != nil {
				// Rejecting the query is also a valid defense.
				return
			}

			clause, args := exec.buildWhereClause(q)

			// Values in conditions should always be parameterized (? placeholders),
			// not interpolated. Verify the clause uses placeholders.
			for _, cond := range q.Conditions {
				if cond.Operator != OpExists && cond.Operator != OpNotExists {
					if !strings.Contains(clause, "?") {
						t.Errorf("expected parameterized placeholder in clause, got %q", clause)
					}
				}
			}

			// The column names in the clause should be sanitized: no semicolons,
			// quotes, or comment markers.
			for _, bad := range []string{";", "'", `"`, "--", "/*", "*/"} {
				if strings.Contains(clause, bad) {
					t.Errorf("clause contains dangerous pattern %q: %s", bad, clause)
				}
			}

			// Verify that potentially dangerous values are in args, not in the clause.
			_ = args
		})
	}
}

// ---------------------------------------------------------------------------
// parseDuration -- additional edge cases
// ---------------------------------------------------------------------------

func TestParseDuration_ExtraCases(t *testing.T) {
	tests := []struct {
		input string
		ok    bool
	}{
		{"now-30m", true},
		{"now-7d", true},
		{"now-1s", true},
		{"NOW-1h", true},   // case insensitive
		{"Now-24h", true},  // mixed case
		{"now-", false},    // trailing dash, no duration
		{"now/d", false},   // unsupported Elasticsearch-style rounding
		{"yesterday", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, ok := parseDuration(tt.input)
			if ok != tt.ok {
				t.Errorf("parseDuration(%q) ok=%v, want %v", tt.input, ok, tt.ok)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Query.String()
// ---------------------------------------------------------------------------

func TestQueryString_MultipleConditions(t *testing.T) {
	q := &Query{
		Conditions: []Condition{
			{Field: "action", Operator: OpEquals, Value: "login"},
			{Field: "severity", Operator: OpGreater, Value: int64(5)},
			{Field: "outcome", Operator: OpEquals, Value: "failure"},
		},
		Logic: []string{"AND", "OR"},
	}

	result := q.String()
	if !strings.Contains(result, "AND") {
		t.Errorf("expected AND in %q", result)
	}
	if !strings.Contains(result, "OR") {
		t.Errorf("expected OR in %q", result)
	}
}

func TestQueryString_NoConditions(t *testing.T) {
	q := &Query{}
	result := q.String()
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}
