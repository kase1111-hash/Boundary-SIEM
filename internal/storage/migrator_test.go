package storage

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

func TestSplitStatements(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		expected []string
	}{
		{
			name:     "single statement",
			sql:      "CREATE TABLE test (id INT)",
			expected: []string{"CREATE TABLE test (id INT)"},
		},
		{
			name:     "multiple statements",
			sql:      "CREATE TABLE a (id INT); CREATE TABLE b (id INT)",
			expected: []string{"CREATE TABLE a (id INT)", "CREATE TABLE b (id INT)"},
		},
		{
			name:     "statement with semicolon in string",
			sql:      "INSERT INTO t VALUES ('hello; world')",
			expected: []string{"INSERT INTO t VALUES ('hello; world')"},
		},
		{
			// Comments are stripped by the splitter. This case used to expect
			// "-- Comment\nCREATE TABLE a (id INT)", and Run() then skipped every
			// statement starting with "--", so no migration table was created.
			name: "multiple with comments",
			sql: `-- Comment
CREATE TABLE a (id INT);
-- Another comment
CREATE TABLE b (id INT)`,
			expected: []string{"CREATE TABLE a (id INT)", "CREATE TABLE b (id INT)"},
		},
		{
			name:     "doubled quote escape",
			sql:      "INSERT INTO t VALUES ('it''s'); SELECT 2",
			expected: []string{"INSERT INTO t VALUES ('it''s')", "SELECT 2"},
		},
		{
			name:     "backslash quote escape",
			sql:      `INSERT INTO t VALUES ('it\'s; here'); SELECT 2`,
			expected: []string{`INSERT INTO t VALUES ('it\'s; here')`, "SELECT 2"},
		},
		{
			name:     "semicolon inside line comment",
			sql:      "-- first; second\nSELECT 1; SELECT 2 -- trailing; note\n",
			expected: []string{"SELECT 1", "SELECT 2"},
		},
		{
			name:     "block comment",
			sql:      "/* header; x */ SELECT 1; /* only a comment */;",
			expected: []string{"SELECT 1"},
		},
		{
			name:     "comment markers inside strings are kept",
			sql:      "SELECT '--not a comment', '/* nor this */'",
			expected: []string{"SELECT '--not a comment', '/* nor this */'"},
		},
		{
			name:     "inline comment inside statement",
			sql:      "CREATE TABLE t (\n    a Int8, -- note; here\n    b Int8\n)",
			expected: []string{"CREATE TABLE t (\n    a Int8, \n    b Int8\n)"},
		},
		{
			name:     "only comments",
			sql:      "-- Migration: 000\n-- Description: nothing\n",
			expected: nil,
		},
		{
			name:     "quoted identifiers",
			sql:      "SELECT `a;b`, \"c;d\" FROM t; SELECT 2",
			expected: []string{"SELECT `a;b`, \"c;d\" FROM t", "SELECT 2"},
		},
		{
			name:     "empty string",
			sql:      "",
			expected: nil,
		},
		{
			name:     "only whitespace",
			sql:      "   \n\t  ",
			expected: nil,
		},
		{
			name:     "trailing semicolon",
			sql:      "CREATE TABLE test (id INT);",
			expected: []string{"CREATE TABLE test (id INT)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitStatements(tt.sql)

			if len(result) != len(tt.expected) {
				t.Errorf("splitStatements() returned %d statements, want %d", len(result), len(tt.expected))
				t.Errorf("Got: %v", result)
				t.Errorf("Want: %v", tt.expected)
				return
			}

			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("statement[%d] = %q, want %q", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestMigration_LoadMigrations(t *testing.T) {
	// Test that migrations can be loaded from embedded files
	m := &Migrator{}
	migrations, err := m.loadMigrations()

	if err != nil {
		t.Fatalf("loadMigrations() error = %v", err)
	}

	if len(migrations) == 0 {
		t.Error("loadMigrations() returned no migrations")
	}

	// Verify migrations are sorted by version
	for i := 1; i < len(migrations); i++ {
		if migrations[i].Version <= migrations[i-1].Version {
			t.Errorf("migrations not sorted: version %d comes after %d",
				migrations[i].Version, migrations[i-1].Version)
		}
	}

	// Verify first migration is version 1
	if migrations[0].Version != 1 {
		t.Errorf("first migration version = %d, want 1", migrations[0].Version)
	}
}

// ---------------------------------------------------------------------------
// Migrator.Run against a recording driver.Conn
// ---------------------------------------------------------------------------

// migrationConn records Exec calls and answers the migrator's two queries
// (applied versions and existing tables) from its fields.
type migrationConn struct {
	mockConn

	mu       sync.Mutex
	execs    []string
	applied  []uint32
	tables   []string
	failExec func(query string) error
}

func (c *migrationConn) Exec(_ context.Context, query string, args ...any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failExec != nil {
		if err := c.failExec(query); err != nil {
			return err
		}
	}
	c.execs = append(c.execs, query)
	if strings.HasPrefix(query, "INSERT INTO schema_migrations") && len(args) > 0 {
		if v, ok := args[0].(uint32); ok {
			c.applied = append(c.applied, v)
		}
	}
	if name, ok := testCreatedName(query); ok {
		c.tables = append(c.tables, name)
	}
	return nil
}

var testCreatePattern = regexp.MustCompile(`(?ims)^\s*CREATE\s+(?:TABLE|MATERIALIZED\s+VIEW)\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)`)

// testCreatedName is a test-local parser for CREATE statements, independent
// of the production helper.
func testCreatedName(stmt string) (string, bool) {
	m := testCreatePattern.FindStringSubmatch(stmt)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func (c *migrationConn) Query(_ context.Context, query string, _ ...any) (driver.Rows, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case strings.Contains(query, "FROM schema_migrations"):
		values := make([]any, len(c.applied))
		for i, v := range c.applied {
			values[i] = v
		}
		return &fakeRows{values: values}, nil
	case strings.Contains(query, "FROM system.tables"):
		values := make([]any, len(c.tables))
		for i, v := range c.tables {
			values[i] = v
		}
		return &fakeRows{values: values}, nil
	}
	return nil, fmt.Errorf("unexpected query %q", query)
}

func (c *migrationConn) executed() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.execs...)
}

func (c *migrationConn) recorded() []uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint32(nil), c.applied...)
}

// fakeRows yields one single-column row per value.
type fakeRows struct {
	values []any
	next   int
}

func (r *fakeRows) Next() bool {
	if r.next >= len(r.values) {
		return false
	}
	r.next++
	return true
}

func (r *fakeRows) Scan(dest ...any) error {
	v := r.values[r.next-1]
	switch d := dest[0].(type) {
	case *uint32:
		*d = v.(uint32)
	case *string:
		*d = v.(string)
	default:
		return fmt.Errorf("fakeRows: unsupported scan target %T", dest[0])
	}
	return nil
}

func (r *fakeRows) ScanStruct(any) error             { return nil }
func (r *fakeRows) ColumnTypes() []driver.ColumnType { return nil }
func (r *fakeRows) Totals(...any) error              { return nil }
func (r *fakeRows) Columns() []string                { return []string{"c"} }
func (r *fakeRows) Close() error                     { return nil }
func (r *fakeRows) Err() error                       { return nil }
func (r *fakeRows) HasData() bool                    { return len(r.values) > 0 }

// embeddedSchemaObjects lists the tables and views the embedded migrations
// create.
func embeddedSchemaObjects(t *testing.T) []string {
	t.Helper()
	migrations, err := (&Migrator{}).loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations() error = %v", err)
	}
	var names []string
	for _, m := range migrations {
		for _, name := range testCreatePattern.FindAllStringSubmatch(m.SQL, -1) {
			names = append(names, name[1])
		}
	}
	return names
}

// Regression (R01/H01): every migration file starts with a "-- Migration:"
// header, and Run() skipped any statement starting with "--", so 001-005
// were recorded as applied without creating a single table.
func TestMigratorRunExecutesEmbeddedMigrations(t *testing.T) {
	conn := &migrationConn{}
	m := NewMigrator(newMockClient(conn))

	if err := m.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	execs := conn.executed()
	for _, stmt := range execs {
		if strings.HasPrefix(strings.TrimSpace(stmt), "--") {
			t.Errorf("executed statement starts with a comment: %q", stmt)
		}
	}

	wantObjects := []string{"events", "events_quarantine", "events_critical", "events_critical_mv", "events_hourly_mv", "alerts"}
	created := map[string]bool{}
	for _, stmt := range execs {
		if name, ok := testCreatedName(stmt); ok {
			created[name] = true
		}
	}
	for _, name := range wantObjects {
		if !created[name] {
			t.Errorf("migration DDL for %q was never executed", name)
		}
	}

	var alters int
	for _, stmt := range execs {
		if strings.HasPrefix(stmt, "ALTER TABLE events ADD") {
			alters++
		}
	}
	if alters != 6 {
		t.Errorf("executed %d ALTER TABLE events statements, want 6 (005: 4 indices, 006: column + index)", alters)
	}

	if got := conn.recorded(); len(got) != 6 {
		t.Errorf("recorded migrations = %v, want versions 1-6", got)
	}

	// A second run is a no-op.
	before := len(conn.executed())
	if err := m.Run(context.Background()); err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	if extra := conn.executed()[before:]; len(extra) != 1 || !strings.Contains(extra[0], "CREATE TABLE IF NOT EXISTS schema_migrations") {
		t.Errorf("second Run() executed %q, want only the schema_migrations bootstrap", extra)
	}
}

// Databases migrated by the buggy migrator have 001-005 recorded but no
// tables. Run must re-apply them (without recording them twice) and then
// apply 006.
func TestMigratorRunRepairsMigrationsRecordedWithoutSchema(t *testing.T) {
	conn := &migrationConn{
		applied: []uint32{1, 2, 3, 4, 5},
		tables:  []string{"schema_migrations"},
	}
	m := NewMigrator(newMockClient(conn))

	if err := m.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	existing := map[string]bool{}
	for _, name := range conn.tables {
		existing[name] = true
	}
	for _, name := range embeddedSchemaObjects(t) {
		if !existing[name] {
			t.Errorf("table %q still missing after repair", name)
		}
	}

	got := conn.recorded()
	if len(got) != 6 || got[5] != 6 {
		t.Errorf("recorded migrations = %v, want [1 2 3 4 5 6] (repaired versions not recorded twice)", got)
	}
}

// When the schema is complete, recorded migrations are not re-applied.
func TestMigratorRunSkipsCompleteMigrations(t *testing.T) {
	conn := &migrationConn{
		applied: []uint32{1, 2, 3, 4, 5, 6},
		tables:  append([]string{"schema_migrations"}, embeddedSchemaObjects(t)...),
	}
	m := NewMigrator(newMockClient(conn))

	if err := m.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if execs := conn.executed(); len(execs) != 1 {
		t.Errorf("executed %d statements, want only the schema_migrations bootstrap: %q", len(execs), execs)
	}
}

// A failing statement stops the run and leaves the migration unrecorded.
func TestMigratorRunDoesNotRecordFailedMigration(t *testing.T) {
	conn := &migrationConn{
		failExec: func(query string) error {
			if strings.Contains(query, "events_quarantine") {
				return errors.New("boom")
			}
			return nil
		},
	}
	m := NewMigrator(newMockClient(conn))

	err := m.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "migration 2") {
		t.Fatalf("Run() error = %v, want failure in migration 2", err)
	}
	if got := conn.recorded(); len(got) != 1 || got[0] != 1 {
		t.Errorf("recorded migrations = %v, want [1]", got)
	}
}

// Every statement in the shipped migrations must be idempotent: Run relies
// on that to re-apply partially applied or repaired migrations.
func TestEmbeddedMigrationsAreIdempotent(t *testing.T) {
	migrations, err := (&Migrator{}).loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations() error = %v", err)
	}
	idempotent := regexp.MustCompile(`(?is)^(CREATE\s+(TABLE|MATERIALIZED\s+VIEW|VIEW)\s+IF\s+NOT\s+EXISTS\b|ALTER\s+TABLE\s+\w+\s+(ADD|DROP)\s+(COLUMN|INDEX)\s+IF\s+(NOT\s+)?EXISTS\b)`)
	for _, m := range migrations {
		stmts := splitStatements(m.SQL)
		if len(stmts) == 0 {
			t.Errorf("migration %03d_%s has no statements", m.Version, m.Name)
		}
		for _, stmt := range stmts {
			if !idempotent.MatchString(stmt) {
				t.Errorf("migration %03d_%s statement is not idempotent: %.80q", m.Version, m.Name, stmt)
			}
		}
	}
}

// Regression (R06): ClickHouse before 25.x rejects a TTL whose expression is
// a DateTime64 ("TTL expression result column should have DateTime or Date
// type"), so every TTL must convert with toDateTime().
func TestEmbeddedMigrationsTTLUsesDateTime(t *testing.T) {
	migrations, err := (&Migrator{}).loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations() error = %v", err)
	}
	ttl := regexp.MustCompile(`(?i)\bTTL\s+([^\n]+)`)
	for _, m := range migrations {
		for _, stmt := range splitStatements(m.SQL) {
			for _, match := range ttl.FindAllStringSubmatch(stmt, -1) {
				if !strings.HasPrefix(match[1], "toDateTime(") {
					t.Errorf("migration %03d_%s: TTL %q must use toDateTime(<DateTime64 column>)", m.Version, m.Name, match[1])
				}
			}
		}
	}
}

func TestSchemaObjectNames(t *testing.T) {
	tests := []struct {
		stmt    string
		created string
		dropped string
	}{
		{stmt: "CREATE TABLE IF NOT EXISTS events (a Int8)", created: "events"},
		{stmt: "CREATE MATERIALIZED VIEW IF NOT EXISTS siem.`events_mv` TO x AS SELECT 1", created: "events_mv"},
		{stmt: "create table t2 (a Int8)", created: "t2"},
		{stmt: "DROP TABLE IF EXISTS old_table", dropped: "old_table"},
		{stmt: "ALTER TABLE events ADD INDEX IF NOT EXISTS i a TYPE minmax"},
	}
	for _, tt := range tests {
		created, _ := createdObject(tt.stmt)
		dropped, _ := droppedObject(tt.stmt)
		if created != tt.created || dropped != tt.dropped {
			t.Errorf("%q: created=%q dropped=%q, want %q %q", tt.stmt, created, dropped, tt.created, tt.dropped)
		}
	}

	objects := finalSchemaObjects([]Migration{
		{Version: 1, SQL: "CREATE TABLE IF NOT EXISTS a (x Int8); CREATE TABLE IF NOT EXISTS b (x Int8)"},
		{Version: 2, SQL: "DROP TABLE IF EXISTS a"},
	})
	if objects["a"] || !objects["b"] {
		t.Errorf("finalSchemaObjects = %v, want only b", objects)
	}
}

func TestMigrationVersionToUInt32(t *testing.T) {
	tests := []struct {
		name    string
		version int
		want    uint32
		wantErr bool
	}{
		{name: "first migration", version: 1, want: 1},
		{name: "zero", version: 0, want: 0},
		{name: "max uint32", version: math.MaxUint32, want: math.MaxUint32},
		{name: "negative", version: -1, wantErr: true},
		{name: "past max uint32", version: math.MaxUint32 + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := migrationVersionToUInt32(tt.version)
			if (err != nil) != tt.wantErr {
				t.Fatalf("migrationVersionToUInt32(%d) error = %v, wantErr %v", tt.version, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("migrationVersionToUInt32(%d) = %d, want %d", tt.version, got, tt.want)
			}
		})
	}
}
