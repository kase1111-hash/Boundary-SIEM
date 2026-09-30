package search

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Recording database/sql driver
//
// These tests run the executor end to end against a fake driver that records
// every statement it receives, so they check the exact SQL text and bound
// arguments that would reach ClickHouse.
// ---------------------------------------------------------------------------

type recordedStatement struct {
	query string
	args  []driver.NamedValue
}

// recordingConnector hands out connections that record each statement and
// answer with an empty result set (or a zero row for count queries).
type recordingConnector struct {
	mu         sync.Mutex
	statements []recordedStatement
}

func (c *recordingConnector) Connect(context.Context) (driver.Conn, error) {
	return &recordingConn{connector: c}, nil
}

func (c *recordingConnector) Driver() driver.Driver { return recordingDriver{} }

func (c *recordingConnector) recorded() []recordedStatement {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]recordedStatement(nil), c.statements...)
}

type recordingDriver struct{}

func (recordingDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("recordingDriver: use sql.OpenDB with a recordingConnector")
}

type recordingConn struct {
	connector *recordingConnector
}

func (c *recordingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("recordingConn: prepared statements are not supported")
}

func (c *recordingConn) Close() error { return nil }

func (c *recordingConn) Begin() (driver.Tx, error) {
	return nil, errors.New("recordingConn: transactions are not supported")
}

func (c *recordingConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.connector.mu.Lock()
	c.connector.statements = append(c.connector.statements, recordedStatement{query: query, args: args})
	c.connector.mu.Unlock()

	if strings.HasPrefix(query, "SELECT count(*) FROM events") {
		return &recordingRows{columns: []string{"count()"}, data: [][]driver.Value{{int64(0)}}}, nil
	}
	return &recordingRows{columns: []string{"result"}}, nil
}

type recordingRows struct {
	columns []string
	data    [][]driver.Value
	next    int
}

func (r *recordingRows) Columns() []string { return r.columns }
func (r *recordingRows) Close() error      { return nil }

func (r *recordingRows) Next(dest []driver.Value) error {
	if r.next >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.next])
	r.next++
	return nil
}

func newRecordingExecutor(t *testing.T) (*Executor, *recordingConnector) {
	t.Helper()
	connector := &recordingConnector{}
	db := sql.OpenDB(connector)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("closing recording db: %v", err)
		}
	})
	return NewExecutor(db), connector
}

// injectionMarker is embedded in every hostile input below. It must never
// appear in SQL text -- only in bound arguments.
const injectionMarker = "INJECTED"

// assertNoMarkerInSQL fails if request data leaked into any statement text.
func assertNoMarkerInSQL(t *testing.T, stmts []recordedStatement) {
	t.Helper()
	for _, s := range stmts {
		if strings.Contains(s.query, injectionMarker) {
			t.Errorf("request data reached SQL text: %s", s.query)
		}
	}
}

// assertTenantScoped checks that a statement's WHERE clause begins with the
// tenant predicate and that no OR appears outside parentheses, i.e. every
// user condition is confined to a group that is ANDed with the tenant filter.
func assertTenantScoped(t *testing.T, stmt string) {
	t.Helper()
	i := strings.Index(stmt, "WHERE ")
	if i < 0 {
		t.Errorf("statement has no WHERE clause: %s", stmt)
		return
	}
	where := stmt[i+len("WHERE "):]
	for _, kw := range []string{" GROUP BY ", " ORDER BY ", " LIMIT "} {
		if j := strings.Index(where, kw); j >= 0 {
			where = where[:j]
		}
	}
	if !strings.HasPrefix(where, "tenant_id = ?") {
		t.Errorf("WHERE clause does not start with the tenant filter: %s", where)
	}
	depth := 0
	for k := 0; k < len(where); k++ {
		switch where[k] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				t.Errorf("WHERE clause closes a parenthesis it never opened: %s", where)
				return
			}
		}
		if depth == 0 && strings.HasPrefix(where[k:], " OR ") {
			t.Errorf("top-level OR escapes the tenant filter: %s", where)
			return
		}
	}
	if depth != 0 {
		t.Errorf("WHERE clause has unbalanced parentheses: %s", where)
	}
}

func mustParse(t *testing.T, s string) *Query {
	t.Helper()
	q, err := ParseQuery(s)
	if err != nil {
		t.Fatalf("ParseQuery(%q) error = %v", s, err)
	}
	return q
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

// Regression: user conditions were previously appended to the tenant filter
// without grouping, so "a OR b" produced "tenant_id = ? AND a OR b", which
// returns b-matches from every tenant.
func TestExecutor_TopLevelORCannotEscapeTenantFilter(t *testing.T) {
	exec, rec := newRecordingExecutor(t)

	q := mustParse(t, "action:login OR action:logout")
	q.TenantID = "tenant-a"
	q.TimeRange = &TimeRange{Start: time.Now().Add(-time.Hour), End: time.Now()}

	if _, err := exec.Search(context.Background(), q); err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	stmts := rec.recorded()
	if len(stmts) != 2 {
		t.Fatalf("expected count + select statements, got %d", len(stmts))
	}
	want := "WHERE tenant_id = ? AND timestamp >= ? AND timestamp <= ? AND (action = ? OR action = ?)"
	for _, s := range stmts {
		if !strings.Contains(s.query, want) {
			t.Errorf("statement %q\ndoes not contain %q", s.query, want)
		}
		assertTenantScoped(t, s.query)
		if len(s.args) == 0 || s.args[0].Value != "tenant-a" {
			t.Errorf("first bound argument = %v, want tenant-a", s.args)
		}
	}
}

func TestParseQuery_RejectsUnbalancedParentheses(t *testing.T) {
	for _, s := range []string{
		"action:login) OR (action:logout", // would close the tenant group early
		"action:login)",
		"(action:login",
		"((action:login)",
		"action:login ()) OR (severity>1",
		")",
	} {
		if _, err := ParseQuery(s); err == nil {
			t.Errorf("ParseQuery(%q) succeeded, want unbalanced parentheses error", s)
		}
	}

	for _, s := range []string{
		"(action:login)",
		"(action:login OR action:logout) AND severity>5",
		"((action:login) OR (action:logout AND severity>1))",
		"() action:login",
	} {
		if _, err := ParseQuery(s); err != nil {
			t.Errorf("ParseQuery(%q) error = %v, want balanced query accepted", s, err)
		}
	}
}

// Queries built directly (not via ParseQuery) must be validated too, since
// Query is an exported type.
func TestExecutor_RejectsMalformedQueryStructure(t *testing.T) {
	cond := func(open, closeParens int) Condition {
		return Condition{Field: "action", Operator: OpEquals, Value: "x", OpenParens: open, CloseParens: closeParens}
	}

	tests := []struct {
		name  string
		query *Query
	}{
		{
			name: "close before open",
			query: &Query{
				Conditions: []Condition{cond(0, 1), cond(1, 0)},
				Logic:      []string{"OR"},
			},
		},
		{
			name:  "unclosed group",
			query: &Query{Conditions: []Condition{cond(1, 0)}},
		},
		{
			name:  "negative paren count",
			query: &Query{Conditions: []Condition{cond(-1, 0)}},
		},
		{
			name: "logic operator injection",
			query: &Query{
				Conditions: []Condition{cond(0, 0), cond(0, 0)},
				Logic:      []string{"OR 1=1) OR (" + injectionMarker},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec, rec := newRecordingExecutor(t)
			tt.query.TenantID = "tenant-a"
			ctx := context.Background()

			if _, err := exec.Search(ctx, tt.query); err == nil {
				t.Error("Search() succeeded, want error")
			}
			if _, err := exec.Aggregate(ctx, tt.query, "action", "count"); err == nil {
				t.Error("Aggregate() succeeded, want error")
			}
			if _, err := exec.TopN(ctx, tt.query, "action", 5); err == nil {
				t.Error("TopN() succeeded, want error")
			}
			if _, err := exec.TimeHistogram(ctx, tt.query, "1h"); err == nil {
				t.Error("TimeHistogram() succeeded, want error")
			}
			if _, err := exec.Explain(ctx, tt.query); err == nil {
				t.Error("Explain() succeeded, want error")
			}
			if stmts := rec.recorded(); len(stmts) != 0 {
				t.Errorf("malformed query reached the database: %v", stmts)
			}
		})
	}
}

func TestExecutor_LogicOperatorsAreNormalized(t *testing.T) {
	exec := newTestExecutor()
	q := &Query{
		Conditions: []Condition{
			{Field: "action", Operator: OpEquals, Value: "a"},
			{Field: "action", Operator: OpEquals, Value: "b"},
		},
		Logic: []string{"or"},
	}
	clause, _ := mustBuildWhereClause(t, exec, q)
	if clause != "WHERE action = ? OR action = ?" {
		t.Errorf("clause = %q", clause)
	}
}

// ---------------------------------------------------------------------------
// Identifiers and numeric clauses
// ---------------------------------------------------------------------------

func TestExecutor_SearchOrderAndPagination(t *testing.T) {
	exec, rec := newRecordingExecutor(t)

	q := &Query{
		TenantID:  "tenant-a",
		OrderBy:   "timestamp; DROP TABLE events -- " + injectionMarker,
		OrderDesc: true,
		Limit:     25,
		Offset:    50,
	}
	if _, err := exec.Search(context.Background(), q); err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	stmts := rec.recorded()
	assertNoMarkerInSQL(t, stmts)
	if len(stmts) != 2 {
		t.Fatalf("expected count + select statements, got %d", len(stmts))
	}

	sel := stmts[1]
	if !strings.HasSuffix(sel.query, "WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?") {
		t.Errorf("select statement = %q", sel.query)
	}
	if len(sel.args) != 3 {
		t.Fatalf("select args = %v, want tenant, limit, offset", sel.args)
	}
	if sel.args[1].Value != int64(25) || sel.args[2].Value != int64(50) {
		t.Errorf("limit/offset args = %v, %v, want 25, 50", sel.args[1].Value, sel.args[2].Value)
	}
}

func TestExecutor_AggregationIdentifiersAreAllowlisted(t *testing.T) {
	ctx := context.Background()
	hostileField := "action) FROM events; DROP TABLE events -- " + injectionMarker

	t.Run("group-by field", func(t *testing.T) {
		exec, rec := newRecordingExecutor(t)
		if _, err := exec.Aggregate(ctx, &Query{TenantID: "t"}, hostileField, "terms"); err != nil {
			t.Fatalf("Aggregate() error = %v", err)
		}
		stmts := rec.recorded()
		assertNoMarkerInSQL(t, stmts)
		if len(stmts) != 1 || !strings.HasPrefix(stmts[0].query, "SELECT timestamp AS key") {
			t.Errorf("unknown field should fall back to timestamp, got %v", stmts)
		}
	})

	t.Run("aggregation function", func(t *testing.T) {
		exec, rec := newRecordingExecutor(t)
		_, err := exec.Aggregate(ctx, &Query{TenantID: "t"}, "severity", "sum(severity)) --"+injectionMarker)
		if err == nil {
			t.Fatal("Aggregate() with unknown function succeeded, want error")
		}
		if stmts := rec.recorded(); len(stmts) != 0 {
			t.Errorf("rejected aggregation reached the database: %v", stmts)
		}
	})

	t.Run("function name is case-insensitive", func(t *testing.T) {
		exec, rec := newRecordingExecutor(t)
		if _, err := exec.Aggregate(ctx, &Query{TenantID: "t"}, "severity", "SUM"); err != nil {
			t.Fatalf("Aggregate(SUM) error = %v", err)
		}
		stmts := rec.recorded()
		if len(stmts) != 1 || !strings.HasPrefix(stmts[0].query, "SELECT SUM(severity) AS value FROM events") {
			t.Errorf("statements = %v", stmts)
		}
	})

	t.Run("top-n limit is bound", func(t *testing.T) {
		exec, rec := newRecordingExecutor(t)
		if _, err := exec.TopN(ctx, &Query{TenantID: "t"}, hostileField, 7); err != nil {
			t.Fatalf("TopN() error = %v", err)
		}
		stmts := rec.recorded()
		assertNoMarkerInSQL(t, stmts)
		if len(stmts) != 1 || !strings.HasSuffix(stmts[0].query, "LIMIT ?") {
			t.Fatalf("statements = %v", stmts)
		}
		args := stmts[0].args
		if got := args[len(args)-1].Value; got != int64(7) {
			t.Errorf("top-n limit arg = %v, want 7", got)
		}
	})

	t.Run("histogram interval", func(t *testing.T) {
		exec, rec := newRecordingExecutor(t)
		if _, err := exec.TimeHistogram(ctx, &Query{TenantID: "t"}, "1h) FROM events --"+injectionMarker); err != nil {
			t.Fatalf("TimeHistogram() error = %v", err)
		}
		stmts := rec.recorded()
		assertNoMarkerInSQL(t, stmts)
		if len(stmts) != 1 || !strings.HasPrefix(stmts[0].query, "SELECT toStartOfHour(timestamp) AS bucket") {
			t.Errorf("statements = %v", stmts)
		}
	})
}

// ---------------------------------------------------------------------------
// End to end: hostile search expressions through every entry point
// ---------------------------------------------------------------------------

func TestExecutor_HostileQueriesStayParameterizedAndTenantScoped(t *testing.T) {
	queries := []string{
		`action:login OR action:logout`,
		`action:"x' OR '1'='1 ` + injectionMarker + `"`,
		`action:"` + injectionMarker + `; DROP TABLE events"`,
		`raw~"` + injectionMarker + `') OR 1=1 --"`,
		`metadata.` + injectionMarker + `:"` + injectionMarker + `"`,
		`meta.key` + injectionMarker + `~value OR severity>=7`,
		`(action:a OR action:b) OR (action:c AND NOT outcome:` + injectionMarker + `)`,
		injectionMarker + `_field:value OR ` + injectionMarker + `:*wild*`,
		`action:login || action:logout && severity>3`,
	}

	for _, qs := range queries {
		t.Run(qs, func(t *testing.T) {
			exec, rec := newRecordingExecutor(t)
			ctx := context.Background()

			q := mustParse(t, qs)
			q.TenantID = "tenant-a"
			q.OrderBy = injectionMarker

			if _, err := exec.Search(ctx, q); err != nil {
				t.Fatalf("Search() error = %v", err)
			}
			if _, err := exec.Aggregate(ctx, q, injectionMarker, "count"); err != nil {
				t.Fatalf("Aggregate() error = %v", err)
			}
			if _, err := exec.TopN(ctx, q, injectionMarker, 5); err != nil {
				t.Fatalf("TopN() error = %v", err)
			}
			if _, err := exec.TimeHistogram(ctx, q, injectionMarker); err != nil {
				t.Fatalf("TimeHistogram() error = %v", err)
			}
			if _, err := exec.Explain(ctx, q); err != nil {
				t.Fatalf("Explain() error = %v", err)
			}

			stmts := rec.recorded()
			if len(stmts) == 0 {
				t.Fatal("no statements recorded")
			}
			assertNoMarkerInSQL(t, stmts)
			for _, s := range stmts {
				assertTenantScoped(t, s.query)
				if placeholders := strings.Count(s.query, "?"); placeholders != len(s.args) {
					t.Errorf("statement has %d placeholders but %d args: %s", placeholders, len(s.args), s.query)
				}
			}
		})
	}
}
