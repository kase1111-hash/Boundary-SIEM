package alerting

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"boundary-siem/internal/correlation"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

// alertsMigrationPath is the migration that creates the table the manager
// persists to. Tests read it so the Go code cannot drift from the schema.
const alertsMigrationPath = "../storage/migrations/004_create_alerts.sql"

// migrationColumns returns the column names declared by the alerts migration.
func migrationColumns(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(alertsMigrationPath)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	cols := make(map[string]bool)
	colRe := regexp.MustCompile(`^\s+([a-z_]+)\s+(UUID|String|LowCardinality|DateTime64|Nullable|UInt32|Array)\b`)
	for _, line := range strings.Split(string(data), "\n") {
		if m := colRe.FindStringSubmatch(line); m != nil {
			cols[m[1]] = true
		}
	}
	if len(cols) < 10 {
		t.Fatalf("parsed only %d columns from %s: %v", len(cols), alertsMigrationPath, cols)
	}
	return cols
}

// ---------------------------------------------------------------------------
// Recording database/sql driver
// ---------------------------------------------------------------------------

type recordedExec struct {
	query string
	args  []driver.Value
}

type recordingDB struct {
	mu      sync.Mutex
	execs   []recordedExec
	queries []string
	execErr error // returned by every Exec when set
}

func (r *recordingDB) Connect(context.Context) (driver.Conn, error) {
	return &recordingConn{db: r}, nil
}
func (r *recordingDB) Driver() driver.Driver { return recordingDriver{} }

func (r *recordingDB) snapshot() []recordedExec {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.execs)
}

type recordingDriver struct{}

func (recordingDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use the connector") }

type recordingConn struct{ db *recordingDB }

func (c *recordingConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }
func (c *recordingConn) Close() error                        { return nil }
func (c *recordingConn) Begin() (driver.Tx, error)           { return nil, errors.New("not supported") }

// CheckNamedValue accepts every argument type (like clickhouse-go does), so
// slices reach the driver unchanged.
func (c *recordingConn) CheckNamedValue(*driver.NamedValue) error { return nil }

func (c *recordingConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	vals := make([]driver.Value, len(args))
	for i, a := range args {
		vals[i] = a.Value
	}
	c.db.mu.Lock()
	defer c.db.mu.Unlock()
	c.db.execs = append(c.db.execs, recordedExec{query: query, args: vals})
	if c.db.execErr != nil {
		return nil, c.db.execErr
	}
	return driver.RowsAffected(1), nil
}

func (c *recordingConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.db.mu.Lock()
	c.db.queries = append(c.db.queries, query)
	c.db.mu.Unlock()
	return emptyRows{}, nil
}

type emptyRows struct{}

func (emptyRows) Columns() []string         { return nil }
func (emptyRows) Close() error              { return nil }
func (emptyRows) Next([]driver.Value) error { return io.EOF }

var insertRe = regexp.MustCompile(`(?s)INSERT INTO alerts\s*\((.*?)\)\s*VALUES`)

// insertedRow maps the INSERT's column names to the bound values.
func insertedRow(t *testing.T, e recordedExec) map[string]driver.Value {
	t.Helper()
	m := insertRe.FindStringSubmatch(e.query)
	if m == nil {
		t.Fatalf("write is not an INSERT INTO alerts: %s", e.query)
	}
	var cols []string
	for _, c := range strings.Split(m[1], ",") {
		cols = append(cols, strings.TrimSpace(c))
	}
	if len(cols) != len(e.args) {
		t.Fatalf("INSERT has %d columns but %d args", len(cols), len(e.args))
	}
	row := make(map[string]driver.Value, len(cols))
	for i, c := range cols {
		row[c] = e.args[i]
	}
	return row
}

// TestAlertPersistenceMatchesMigration is a regression test for alerts never
// reaching ClickHouse: persistAlert wrote columns (id, event_ids, tags, mitre)
// that do not exist in migration 004, and AddNote was never persisted at all.
// Every write must be a full-row INSERT (status is part of the table's sorting
// key, so it cannot be UPDATEd in place) using only migration columns, and
// must carry the new state.
func TestAlertPersistenceMatchesMigration(t *testing.T) {
	schema := migrationColumns(t)
	rec := &recordingDB{}
	db := sql.OpenDB(rec)
	defer db.Close()

	ctx := context.Background()
	mgr := NewManager(DefaultManagerConfig(), db)
	corrAlert := makeCorrelationAlert("persist-rule", "persist-group", "Persist", 9)
	if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
		t.Fatalf("HandleCorrelationAlert: %v", err)
	}

	steps := []struct {
		name  string
		apply func() error
		check map[string]string // column -> expected string value
	}{
		{"create", func() error { return nil }, map[string]string{"status": "new", "severity": "critical", "rule_id": "persist-rule"}},
		{"note", func() error { return mgr.AddNote(ctx, corrAlert.ID, "analyst", "triage note") }, map[string]string{"status": "new"}},
		{"acknowledge", func() error { return mgr.AcknowledgeAlert(ctx, corrAlert.ID, "alice") }, map[string]string{"status": "acknowledged", "acknowledged_by": "alice"}},
		{"assign", func() error { return mgr.AssignAlert(ctx, corrAlert.ID, "bob") }, map[string]string{"status": "in_progress", "assignee": "bob", "acknowledged_by": "alice"}},
		{"resolve", func() error { return mgr.ResolveAlert(ctx, corrAlert.ID, "carol") }, map[string]string{"status": "resolved", "resolved_by": "carol", "assignee": "bob"}},
	}

	var lastUpdated string
	for i, s := range steps {
		if err := s.apply(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		execs := rec.snapshot()
		if len(execs) != i+1 {
			t.Fatalf("%s: expected %d writes so far, got %d", s.name, i+1, len(execs))
		}
		row := insertedRow(t, execs[i])
		for col := range row {
			if !schema[col] {
				t.Errorf("%s: column %q is not in %s", s.name, col, alertsMigrationPath)
			}
		}
		if got := fmt.Sprint(row["alert_id"]); got != corrAlert.ID.String() {
			t.Errorf("%s: alert_id = %q, want %s", s.name, got, corrAlert.ID)
		}
		for col, want := range s.check {
			if got := fmt.Sprint(row[col]); got != want {
				t.Errorf("%s: %s = %q, want %q", s.name, col, got, want)
			}
		}
		if s.name == "note" || s.name == "resolve" {
			if notes := fmt.Sprint(row["notes"]); !strings.Contains(notes, "triage note") {
				t.Errorf("%s: notes column %q does not contain the note", s.name, notes)
			}
		}
		updated := fmt.Sprint(row["updated_at"])
		if i > 0 && updated <= lastUpdated {
			t.Errorf("%s: updated_at %q must increase (previous %q) so the newest version wins", s.name, updated, lastUpdated)
		}
		lastUpdated = updated
	}

	// A rejected transition must not write anything.
	if err := mgr.AcknowledgeAlert(ctx, corrAlert.ID, "mallory"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("re-acknowledge resolved: error = %v, want ErrInvalidTransition", err)
	}
	if n := len(rec.snapshot()); n != len(steps) {
		t.Errorf("rejected transition wrote to the database (%d writes, want %d)", n, len(steps))
	}
}

// TestHandlerReportsStorageErrors checks that a failed database write is
// reported as a server error, not as "alert not found" (the handler used to
// map every manager error to 404).
func TestHandlerReportsStorageErrors(t *testing.T) {
	rec := &recordingDB{}
	db := sql.OpenDB(rec)
	defer db.Close()

	ctx := context.Background()
	mgr := NewManager(DefaultManagerConfig(), db)
	corrAlert := makeCorrelationAlert("storage-err", "storage-err", "Storage error", 5)
	if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
		t.Fatalf("HandleCorrelationAlert: %v", err)
	}
	rec.mu.Lock()
	rec.execErr = errors.New("clickhouse unavailable")
	rec.mu.Unlock()

	mux := http.NewServeMux()
	NewHandler(mgr).RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/"+corrAlert.ID.String()+"/acknowledge", strings.NewReader(`{"user":"a"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "storage_error") {
		t.Fatalf("expected 500 storage_error, got %d %s", w.Code, w.Body.String())
	}
	// The change is applied in memory; a retry is rejected as a conflict
	// rather than silently re-acknowledging.
	got, err := mgr.GetAlert(ctx, corrAlert.ID)
	if err != nil || got.Status != StatusAcknowledged {
		t.Fatalf("expected in-memory acknowledgement, got %+v, %v", got, err)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/alerts/"+corrAlert.ID.String()+"/acknowledge", strings.NewReader(`{"user":"a"}`))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("retry: expected 409, got %d %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Real ClickHouse (opt-in): SIEM_TEST_CLICKHOUSE_ADDR=host:port
// ---------------------------------------------------------------------------

func openTestClickHouse(t *testing.T) *sql.DB {
	t.Helper()
	addr := os.Getenv("SIEM_TEST_CLICKHOUSE_ADDR")
	if addr == "" {
		t.Skip("set SIEM_TEST_CLICKHOUSE_ADDR=host:port to run against a real ClickHouse server")
	}
	ctx := context.Background()
	admin := clickhouse.OpenDB(&clickhouse.Options{Addr: []string{addr}})
	dbName := "siem_alerting_test_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+dbName); err != nil {
		admin.Close()
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+dbName); err != nil {
			t.Logf("drop database: %v", err)
		}
		admin.Close()
	})

	db := clickhouse.OpenDB(&clickhouse.Options{Addr: []string{addr}, Auth: clickhouse.Auth{Database: dbName}})
	t.Cleanup(func() { db.Close() })

	migration, err := os.ReadFile(alertsMigrationPath)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := db.ExecContext(ctx, string(migration)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
	return db
}

func TestAlertPersistenceClickHouse(t *testing.T) {
	db := openTestClickHouse(t)
	ctx := context.Background()

	mgr := NewManager(DefaultManagerConfig(), db)

	worked := makeCorrelationAlert("ch-rule", "ch-group", "Worked alert with 'quotes' and ? marks", 9)
	worked.MITRE = &correlation.MITREMapping{TacticID: "TA0006", TacticName: "Credential Access", TechniqueID: "T1110", Techniques: []string{"T1110.001"}}
	worked.Tags = []string{"brute-force", "auth"}
	open := makeCorrelationAlert("ch-rule-2", "ch-group-2", "Open alert", 4)
	for _, a := range []*correlation.Alert{worked, open} {
		if err := mgr.HandleCorrelationAlert(ctx, a); err != nil {
			t.Fatalf("HandleCorrelationAlert: %v", err)
		}
	}
	for _, step := range []func() error{
		func() error {
			return mgr.AddNote(ctx, worked.ID, "analyst", "looks like a real attack; checking 'src' ?")
		},
		func() error { return mgr.AcknowledgeAlert(ctx, worked.ID, "alice") },
		func() error { return mgr.AssignAlert(ctx, worked.ID, "bob") },
		func() error { return mgr.ResolveAlert(ctx, worked.ID, "carol") },
	} {
		if err := step(); err != nil {
			t.Fatalf("lifecycle step: %v", err)
		}
	}
	want, err := mgr.GetAlert(ctx, worked.ID)
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}

	var distinct uint64
	if err := db.QueryRowContext(ctx, "SELECT uniqExact(alert_id) FROM alerts").Scan(&distinct); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	if distinct != 2 {
		t.Fatalf("expected 2 alerts in ClickHouse, got %d", distinct)
	}

	// Simulate a restart: a fresh manager must see the latest state of every alert.
	restarted := NewManager(DefaultManagerConfig(), db)

	t.Run("GetAlert falls back to the latest persisted version", func(t *testing.T) {
		got, err := restarted.GetAlert(ctx, worked.ID)
		if err != nil {
			t.Fatalf("GetAlert from DB: %v", err)
		}
		assertSameAlert(t, got, want)
		if _, err := restarted.GetAlert(ctx, uuid.New()); !errors.Is(err, ErrAlertNotFound) {
			t.Errorf("unknown alert: error = %v, want ErrAlertNotFound", err)
		}
	})

	t.Run("ListAlerts filters on the latest version only", func(t *testing.T) {
		tests := []struct {
			status AlertStatus
			want   []uuid.UUID
		}{
			{StatusNew, []uuid.UUID{open.ID}}, // worked has an old 'new' version; it must not match
			{StatusAcknowledged, nil},
			{StatusInProgress, nil},
			{StatusResolved, []uuid.UUID{worked.ID}},
		}
		for _, tt := range tests {
			s := tt.status
			got, err := restarted.ListAlerts(ctx, AlertFilter{Status: &s})
			if err != nil {
				t.Fatalf("ListAlerts(%s): %v", s, err)
			}
			var ids []uuid.UUID
			for _, a := range got {
				ids = append(ids, a.ID)
			}
			if !slices.Equal(ids, tt.want) {
				t.Errorf("ListAlerts(status=%s) = %v, want %v", s, ids, tt.want)
			}
		}
		crit := correlation.SeverityCritical
		since := time.Now().Add(-time.Hour)
		got, err := restarted.ListAlerts(ctx, AlertFilter{Severity: &crit, RuleID: "ch-rule", Since: &since})
		if err != nil || len(got) != 1 || got[0].ID != worked.ID {
			t.Errorf("ListAlerts(severity, rule, since) = %v, %v; want [%s]", got, err, worked.ID)
		}
	})

	t.Run("LoadFromDB restores alerts and their lifecycle", func(t *testing.T) {
		n, err := restarted.LoadFromDB(ctx)
		if err != nil {
			t.Fatalf("LoadFromDB: %v", err)
		}
		if n != 2 {
			t.Fatalf("LoadFromDB loaded %d alerts, want 2", n)
		}
		got, err := restarted.GetAlert(ctx, worked.ID)
		if err != nil {
			t.Fatalf("GetAlert after load: %v", err)
		}
		assertSameAlert(t, got, want)

		if err := restarted.AcknowledgeAlert(ctx, worked.ID, "mallory"); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("acknowledge restored resolved alert: error = %v, want ErrInvalidTransition", err)
		}
		if err := restarted.AcknowledgeAlert(ctx, open.ID, "dave"); err != nil {
			t.Fatalf("acknowledge restored open alert: %v", err)
		}
		// A duplicate of a just-restored alert is still deduplicated.
		dup := makeCorrelationAlert("ch-rule-2", "ch-group-2", "Open alert again", 4)
		if err := restarted.HandleCorrelationAlert(ctx, dup); err != nil {
			t.Fatalf("HandleCorrelationAlert: %v", err)
		}
		if _, err := restarted.GetAlert(ctx, dup.ID); !errors.Is(err, ErrAlertNotFound) {
			t.Errorf("duplicate within the dedup window was not suppressed after restart (err=%v)", err)
		}

		again := NewManager(DefaultManagerConfig(), db)
		if _, err := again.LoadFromDB(ctx); err != nil {
			t.Fatalf("second LoadFromDB: %v", err)
		}
		reloaded, err := again.GetAlert(ctx, open.ID)
		if err != nil {
			t.Fatalf("GetAlert: %v", err)
		}
		if reloaded.Status != StatusAcknowledged || reloaded.AckedBy != "dave" {
			t.Errorf("acknowledgement after restart was not persisted: %+v", reloaded)
		}
	})

	t.Run("alerts only in the database can still be updated", func(t *testing.T) {
		fresh := NewManager(DefaultManagerConfig(), db) // nothing loaded into memory
		if err := fresh.AddNote(ctx, worked.ID, "auditor", "post-incident review"); err != nil {
			t.Fatalf("AddNote on DB-only alert: %v", err)
		}
		if err := fresh.AcknowledgeAlert(ctx, worked.ID, "mallory"); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("acknowledge DB-only resolved alert: error = %v, want ErrInvalidTransition", err)
		}
		if err := fresh.AddNote(ctx, uuid.New(), "auditor", "x"); !errors.Is(err, ErrAlertNotFound) {
			t.Errorf("AddNote on unknown alert: error = %v, want ErrAlertNotFound", err)
		}
		got, err := NewManager(DefaultManagerConfig(), db).GetAlert(ctx, worked.ID)
		if err != nil {
			t.Fatalf("GetAlert: %v", err)
		}
		if got.Status != StatusResolved || len(got.Notes) != 2 || got.Notes[1].Content != "post-incident review" {
			t.Errorf("note on DB-only alert was not persisted: status=%s notes=%+v", got.Status, got.Notes)
		}
	})
}

// TestEscalationAfterRestartClickHouse checks end to end that an escalation
// step that fired before a restart is not paged again once LoadFromDB has
// restored the alert from ClickHouse.
func TestEscalationAfterRestartClickHouse(t *testing.T) {
	db := openTestClickHouse(t)
	ctx := context.Background()

	// run runs two escalation checks and returns the number of
	// notifications sent to the default channel.
	run := func(mgr *Manager, want int) int {
		engine := NewEscalationEngine(mgr)
		ch := newMockChannel(DefaultChannelName)
		engine.RegisterChannel(ch)
		for _, p := range BuiltinEscalationPolicies() {
			engine.AddPolicy(p)
		}
		for i := 0; i < 2; i++ {
			engine.checkEscalations(ctx)
		}
		return waitForSends(t, map[string]*mockChannel{DefaultChannelName: ch}, map[string]int{DefaultChannelName: want})[DefaultChannelName]
	}

	before := NewManager(DefaultManagerConfig(), db)
	corrAlert := makeCorrelationAlert("ch-esc-rule", "ch-esc-group", "Unacknowledged", 9)
	corrAlert.Timestamp = time.Now().Add(-20 * time.Minute) // critical: the 15m step is due
	if err := before.HandleCorrelationAlert(ctx, corrAlert); err != nil {
		t.Fatalf("HandleCorrelationAlert: %v", err)
	}
	if n := run(before, 1); n != 1 {
		t.Fatalf("before restart: %d escalation notifications, want 1", n)
	}

	after := NewManager(DefaultManagerConfig(), db)
	if _, err := after.LoadFromDB(ctx); err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}
	if n := run(after, 0); n != 0 {
		t.Errorf("after restart: %d escalation notifications, want 0 (the step already fired)", n)
	}
	if notes := escalationNoteContents(t, after, corrAlert.ID); len(notes) != 1 {
		t.Errorf("escalation notes after restart = %q, want 1", notes)
	}
}

// TestListAlertsPaginatesClickHouse pages through alerts that are only in
// ClickHouse and share a creation time: the database must order them the
// same way as the in-memory listing so pages neither repeat nor skip alerts.
func TestListAlertsPaginatesClickHouse(t *testing.T) {
	db := openTestClickHouse(t)
	ctx := context.Background()

	writer := NewManager(DefaultManagerConfig(), db)
	created := time.Now().Add(-time.Minute)
	const total = 12
	for i := 0; i < total; i++ {
		a := makeCorrelationAlert("ch-page-rule", fmt.Sprintf("group-%d", i), "Page", 4)
		a.Timestamp = created
		if err := writer.HandleCorrelationAlert(ctx, a); err != nil {
			t.Fatalf("HandleCorrelationAlert: %v", err)
		}
	}

	reader := NewManager(DefaultManagerConfig(), db) // nothing in memory
	seen := make(map[uuid.UUID]bool)
	for offset := 0; offset < total; offset += 5 {
		page, err := reader.ListAlerts(ctx, AlertFilter{RuleID: "ch-page-rule", Limit: 5, Offset: offset})
		if err != nil {
			t.Fatalf("ListAlerts(offset=%d): %v", offset, err)
		}
		for _, a := range page {
			if seen[a.ID] {
				t.Errorf("alert %s returned on more than one page", a.ID)
			}
			seen[a.ID] = true
		}
	}
	if len(seen) != total {
		t.Errorf("paging returned %d distinct alerts, want %d", len(seen), total)
	}
}

func assertSameAlert(t *testing.T, got, want *Alert) {
	t.Helper()
	us := func(ts time.Time) time.Time { return ts.Truncate(time.Microsecond) }
	usPtr := func(ts *time.Time) any {
		if ts == nil {
			return nil
		}
		return us(*ts).UnixMicro()
	}
	checks := []struct {
		field     string
		got, want any
	}{
		{"ID", got.ID, want.ID},
		{"RuleID", got.RuleID, want.RuleID},
		{"RuleName", got.RuleName, want.RuleName},
		{"Severity", got.Severity, want.Severity},
		{"Status", got.Status, want.Status},
		{"Title", got.Title, want.Title},
		{"Description", got.Description, want.Description},
		{"CreatedAt", us(got.CreatedAt).UnixMicro(), us(want.CreatedAt).UnixMicro()},
		{"UpdatedAt", us(got.UpdatedAt).UnixMicro(), us(want.UpdatedAt).UnixMicro()},
		{"AckedAt", usPtr(got.AckedAt), usPtr(want.AckedAt)},
		{"AckedBy", got.AckedBy, want.AckedBy},
		{"ResolvedAt", usPtr(got.ResolvedAt), usPtr(want.ResolvedAt)},
		{"ResolvedBy", got.ResolvedBy, want.ResolvedBy},
		{"AssignedTo", got.AssignedTo, want.AssignedTo},
		{"GroupKey", got.GroupKey, want.GroupKey},
		{"EventCount", got.EventCount, want.EventCount},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	for _, c := range []struct {
		field     string
		got, want any
	}{
		{"EventIDs", got.EventIDs, want.EventIDs},
		{"Tags", got.Tags, want.Tags},
		{"MITRE", got.MITRE, want.MITRE},
		{"Notes", got.Notes, want.Notes},
	} {
		g, _ := json.Marshal(c.got)
		w, _ := json.Marshal(c.want)
		if string(g) != string(w) {
			t.Errorf("%s = %s, want %s", c.field, g, w)
		}
	}
}
