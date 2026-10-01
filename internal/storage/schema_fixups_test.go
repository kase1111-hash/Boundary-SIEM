package storage

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// E2E round 2: events_hourly_mv counted every retried (ambiguous) INSERT
// again, because the SummingMergeTree inside it kept no deduplication
// window; and the alerts ReplacingMergeTree never collapsed the versions of
// an alert, because status was part of its sorting key.

func completeSchemaConn(t *testing.T) *migrationConn {
	return &migrationConn{
		applied: []uint32{1, 2, 3, 4, 5, 6, 7},
		tables:  append([]string{"schema_migrations"}, embeddedSchemaObjects(t)...),
	}
}

func TestSchemaFixupSetsInnerTableDedupWindow(t *testing.T) {
	conn := completeSchemaConn(t)
	conn.innerNoWindow = []string{
		".inner_id.0f8c2a4e-1b2c-4d5e-8f90-123456789abc",
		".inner.legacy_view",
		".inner.x` MODIFY SETTING a = 1; DROP TABLE events; --", // never put into SQL
	}
	if err := NewMigrator(newMockClient(conn)).Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	want := []string{
		"ALTER TABLE `.inner_id.0f8c2a4e-1b2c-4d5e-8f90-123456789abc` MODIFY SETTING non_replicated_deduplication_window = 1000",
		"ALTER TABLE `.inner.legacy_view` MODIFY SETTING non_replicated_deduplication_window = 1000",
	}
	if got := conn.executed()[1:]; !slices.Equal(got, want) {
		t.Errorf("executed %q, want %q", got, want)
	}
}

func TestSchemaFixupRebuildsAlertsSortedByStatus(t *testing.T) {
	conn := completeSchemaConn(t)
	conn.alertsSortingKey = "tenant_id, status, created_at, alert_id" // migration 004
	if err := NewMigrator(newMockClient(conn)).Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	got := conn.executed()[1:]
	if len(got) != 5 {
		t.Fatalf("executed %d statements, want the 5 of the rebuild: %q", len(got), got)
	}
	for i, prefix := range []string{
		"DROP TABLE IF EXISTS alerts_v2",
		"CREATE TABLE alerts_v2 (",
		"INSERT INTO alerts_v2 (",
		"EXCHANGE TABLES alerts AND alerts_v2",
		"DROP TABLE alerts_v2",
	} {
		if !strings.HasPrefix(got[i], prefix) {
			t.Errorf("statement %d = %.60q, want it to start with %q", i, got[i], prefix)
		}
	}
	if !strings.Contains(got[1], "ORDER BY (tenant_id, created_at, alert_id)") ||
		!strings.Contains(got[1], "ReplacingMergeTree(updated_at)") {
		t.Errorf("new alerts table = %s", got[1])
	}
	if !strings.Contains(got[2], "FROM alerts") {
		t.Errorf("rebuild does not copy the alerts: %s", got[2])
	}
}

func TestSchemaFixupLeavesFixedAlertsAlone(t *testing.T) {
	conn := completeSchemaConn(t)
	conn.alertsSortingKey = "tenant_id, created_at, alert_id"
	if err := NewMigrator(newMockClient(conn)).Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := conn.executed()[1:]; len(got) != 0 {
		t.Errorf("executed %q, want nothing", got)
	}

	// A rebuild interrupted after the swap left the old table behind.
	conn.tables = append(conn.tables, "alerts_v2")
	if err := NewMigrator(newMockClient(conn)).Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := conn.executed(); got[len(got)-1] != "DROP TABLE alerts_v2" {
		t.Errorf("last statement = %q, want the leftover alerts_v2 dropped", got[len(got)-1])
	}
}

func TestSortingKeyHas(t *testing.T) {
	for _, tt := range []struct {
		key  string
		want bool
	}{
		{"tenant_id, status, created_at, alert_id", true},
		{"status", true},
		{"tenant_id, created_at, alert_id", false},
		{"tenant_id, status_code", false},
		{"", false},
	} {
		if got := sortingKeyHas(tt.key, "status"); got != tt.want {
			t.Errorf("sortingKeyHas(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

// --- Against a real ClickHouse server (CLICKHOUSE_TEST_ADDR) ---

// chTimeLayout formats a time for a DateTime64(6) literal.
const chTimeLayout = "2006-01-02 15:04:05.000000"

func integrationMigrated(t *testing.T) *ClickHouseClient {
	t.Helper()
	cfg := integrationConfig(t)
	client, err := NewClickHouseClient(cfg)
	if err != nil {
		t.Fatalf("NewClickHouseClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := NewMigrator(client).Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	return client
}

func integrationExec(t *testing.T, client *ClickHouseClient, stmt string, args ...any) {
	t.Helper()
	if err := client.Exec(context.Background(), stmt, args...); err != nil {
		t.Fatalf("%.80s: %v", stmt, err)
	}
}

func integrationString(t *testing.T, client *ClickHouseClient, query string) string {
	t.Helper()
	got, err := (&Migrator{client: client}).queryStrings(context.Background(), query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return strings.Join(got, ",")
}

// hourlyEvents returns n events of tenant, half of them a month back (a
// second partition and hour).
func hourlyEvents(tenant string, n int) []*schema.Event {
	var events []*schema.Event
	for i := 0; i < n; i++ {
		e := integrationEvent(tenant, i)
		if i%2 == 0 {
			e.Timestamp = e.Timestamp.AddDate(0, -1, 0)
		}
		events = append(events, e)
	}
	return events
}

// assertHourlyCountsRetriesOnce inserts events under one token three times
// (twice in full, once in part) and checks every table counts them once.
func assertHourlyCountsRetriesOnce(t *testing.T, client *ClickHouseClient, tenant string) {
	t.Helper()
	bw := NewBatchWriter(client, BatchWriterConfig{BatchSize: 1000, FlushInterval: time.Hour})
	defer bw.Close()
	events := hourlyEvents(tenant, 40)
	token := "hourly-" + tenant
	for _, batch := range [][]*schema.Event{events, events, events[:10]} {
		if err := bw.insertBatch(batch, token); err != nil {
			t.Fatalf("insertBatch() error = %v", err)
		}
	}
	if n := integrationCount(t, client, "SELECT count() FROM events WHERE tenant_id = ?", tenant); n != 40 {
		t.Errorf("events = %d, want 40", n)
	}
	if n := integrationCount(t, client, "SELECT sum(event_count) FROM events_hourly_mv WHERE tenant_id = ?", tenant); n != 40 {
		t.Errorf("events_hourly_mv counts %d events, want 40 (a retried INSERT counted again)", n)
	}
}

func TestIntegrationHourlyViewCountsRetriedInsertOnce(t *testing.T) {
	client := integrationMigrated(t)
	assertHourlyCountsRetriesOnce(t, client, "hourly-fresh")
}

// statementOf returns the statement of migration version that mentions
// marker.
func statementOf(t *testing.T, version int, marker string) string {
	t.Helper()
	migrations, err := (&Migrator{}).loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if m.Version != version {
			continue
		}
		for _, stmt := range splitStatements(m.SQL) {
			if strings.Contains(stmt, marker) {
				return stmt
			}
		}
	}
	t.Fatalf("migration %d has no statement with %q", version, marker)
	return ""
}

// A database migrated before the fixups (alerts sorted by status, an hourly
// view without a deduplication window) is repaired on the next start, and
// keeps its data.
func TestIntegrationSchemaFixupsRepairOldSchema(t *testing.T) {
	client := integrationMigrated(t)

	// Recreate the schema migrations 003 and 004 left.
	integrationExec(t, client, "DROP TABLE alerts SYNC")
	integrationExec(t, client, statementOf(t, 4, "CREATE TABLE IF NOT EXISTS alerts"))
	integrationExec(t, client, "DROP TABLE events_hourly_mv SYNC")
	integrationExec(t, client, statementOf(t, 3, "events_hourly_mv"))
	if key := integrationString(t, client, "SELECT sorting_key FROM system.tables WHERE database = currentDatabase() AND name = 'alerts'"); !sortingKeyHas(key, "status") {
		t.Fatalf("old alerts sorting key = %q", key)
	}
	if inner := integrationString(t, client, innerTablesWithoutDedupWindow); inner == "" {
		t.Fatal("old hourly view has a deduplication window already")
	}
	// The bug: the old hourly view counts a retried INSERT again.
	bw := NewBatchWriter(client, BatchWriterConfig{BatchSize: 1000, FlushInterval: time.Hour})
	old := hourlyEvents("hourly-old", 10)
	for range 2 {
		if err := bw.insertBatch(old, "hourly-old"); err != nil {
			t.Fatalf("insertBatch() error = %v", err)
		}
	}
	_ = bw.Close()
	if n := integrationCount(t, client, "SELECT sum(event_count) FROM events_hourly_mv WHERE tenant_id = 'hourly-old'"); n != 20 {
		t.Fatalf("old hourly view counts %d events for 10 inserted twice, want 20 (the bug)", n)
	}

	// One alert in four versions, one in one.
	multi, single := uuid.New(), uuid.New()
	created := time.Now().UTC().Add(-time.Hour)
	for i, status := range []string{"new", "acknowledged", "in_progress", "resolved"} {
		integrationExec(t, client, fmt.Sprintf(
			"INSERT INTO alerts (alert_id, rule_id, status, created_at, updated_at, sample_event_ids, metadata, notes) VALUES ('%s', 'r', '%s', '%s', '%s', [], '{}', '[]')",
			multi, status, created.Format(chTimeLayout), created.Add(time.Duration(i)*time.Minute).Format(chTimeLayout)))
	}
	integrationExec(t, client, fmt.Sprintf(
		"INSERT INTO alerts (alert_id, rule_id, status, created_at, updated_at, sample_event_ids, metadata, notes) VALUES ('%s', 'r', 'new', '%s', '%s', [], '{}', '[]')",
		single, created.Format(chTimeLayout), created.Format(chTimeLayout)))

	// The bug: FINAL keeps one row per status the alert held.
	if n := integrationCount(t, client, "SELECT count() FROM alerts FINAL"); n != 5 {
		t.Fatalf("old layout: alerts FINAL = %d rows, want 5 (one per status)", n)
	}

	for run := 1; run <= 2; run++ { // the second run changes nothing
		if err := NewMigrator(client).Run(context.Background()); err != nil {
			t.Fatalf("Run() #%d error = %v", run, err)
		}
		if key := integrationString(t, client, "SELECT sorting_key FROM system.tables WHERE database = currentDatabase() AND name = 'alerts'"); key != "tenant_id, created_at, alert_id" {
			t.Errorf("run %d: alerts sorting key = %q", run, key)
		}
		if n := integrationCount(t, client, "SELECT count() FROM alerts FINAL"); n != 2 {
			t.Errorf("run %d: alerts FINAL = %d rows, want one per alert (2)", run, n)
		}
		if got := integrationString(t, client, fmt.Sprintf("SELECT status FROM alerts FINAL WHERE alert_id = '%s'", multi)); got != "resolved" {
			t.Errorf("run %d: latest version of the alert = %q, want resolved", run, got)
		}
		if got := integrationString(t, client, fmt.Sprintf("SELECT status FROM alerts FINAL WHERE alert_id = '%s'", single)); got != "new" {
			t.Errorf("run %d: single-version alert = %q, want new", run, got)
		}
		if inner := integrationString(t, client, innerTablesWithoutDedupWindow); inner != "" {
			t.Errorf("run %d: inner tables without a deduplication window: %s", run, inner)
		}
		if tables := integrationTables(t, client); slices.Contains(tables, "alerts_v2") {
			t.Errorf("run %d: alerts_v2 left behind: %v", run, tables)
		}
	}

	// Later versions collapse too.
	integrationExec(t, client, fmt.Sprintf(
		"INSERT INTO alerts (alert_id, rule_id, status, created_at, updated_at, sample_event_ids, metadata, notes) VALUES ('%s', 'r', 'acknowledged', '%s', '%s', [], '{}', '[]')",
		single, created.Format(chTimeLayout), created.Add(time.Hour).Format(chTimeLayout)))
	integrationExec(t, client, "OPTIMIZE TABLE alerts FINAL")
	if n := integrationCount(t, client, "SELECT count() FROM alerts"); n != 2 {
		t.Errorf("alerts after a merge = %d rows, want one per alert (2)", n)
	}
	if got := integrationString(t, client, fmt.Sprintf("SELECT status FROM alerts FINAL WHERE alert_id = '%s'", single)); got != "acknowledged" {
		t.Errorf("updated alert = %q, want acknowledged", got)
	}

	assertHourlyCountsRetriesOnce(t, client, "hourly-repaired")
}
