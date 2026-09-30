package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// Integration tests against a real ClickHouse server. They run only when
// CLICKHOUSE_TEST_ADDR is set to a native-protocol address, e.g.
//
//	CLICKHOUSE_TEST_ADDR=127.0.0.1:9000 go test ./internal/storage -run Integration
//
// CLICKHOUSE_TEST_USER and CLICKHOUSE_TEST_PASSWORD override the default
// credentials. Each test works in its own freshly created database, which is
// dropped afterwards.

// integrationConfig returns a config for a database that does not exist yet,
// or skips the test when no server is configured.
func integrationConfig(t *testing.T) ClickHouseConfig {
	t.Helper()
	addr := os.Getenv("CLICKHOUSE_TEST_ADDR")
	if addr == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR not set; skipping ClickHouse integration test")
	}

	cfg := DefaultClickHouseConfig()
	cfg.Hosts = []string{addr}
	if user := os.Getenv("CLICKHOUSE_TEST_USER"); user != "" {
		cfg.Username = user
	}
	cfg.Password = os.Getenv("CLICKHOUSE_TEST_PASSWORD")
	cfg.Database = fmt.Sprintf("siem_it_%s", strings.ReplaceAll(uuid.NewString(), "-", "")[:16])

	t.Cleanup(func() {
		admin := cfg
		admin.Database = "default"
		client, err := NewClickHouseClient(admin)
		if err != nil {
			t.Logf("cleanup: connect: %v", err)
			return
		}
		defer client.Close()
		if err := client.Exec(context.Background(), "DROP DATABASE IF EXISTS `"+cfg.Database+"`"); err != nil {
			t.Logf("cleanup: drop database %s: %v", cfg.Database, err)
		}
	})
	return cfg
}

func integrationTables(t *testing.T, client *ClickHouseClient) []string {
	t.Helper()
	rows, err := client.Query(context.Background(), "SELECT name FROM system.tables WHERE database = currentDatabase() AND NOT startsWith(name, '.inner')")
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func integrationCount(t *testing.T, client *ClickHouseClient, query string, args ...any) uint64 {
	t.Helper()
	rows, err := client.Query(context.Background(), query, args...)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer rows.Close()
	var n uint64
	if rows.Next() {
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("%s: scan: %v", query, err)
		}
	}
	return n
}

var integrationSchema = []string{
	"alerts", "events", "events_critical", "events_critical_mv", "events_hourly_mv", "events_quarantine", "schema_migrations",
}

// R12 + R01 + R06: on a fresh server the client creates the database, and the
// migrations create the whole schema (on 23.8, 24.8 and 25.x).
func TestIntegrationFreshDatabaseMigrations(t *testing.T) {
	cfg := integrationConfig(t)
	ctx := context.Background()

	client, err := NewClickHouseClient(cfg)
	if err != nil {
		t.Fatalf("NewClickHouseClient() on a missing database error = %v", err)
	}
	defer client.Close()

	m := NewMigrator(client)
	if err := m.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := integrationTables(t, client); strings.Join(got, ",") != strings.Join(integrationSchema, ",") {
		t.Errorf("tables = %v, want %v", got, integrationSchema)
	}

	// Indices from 005/006 and the request_id column exist.
	if n := integrationCount(t, client, "SELECT count() FROM system.data_skipping_indices WHERE database = currentDatabase() AND table = 'events'"); n != 10 {
		t.Errorf("events has %d skipping indices, want 10", n)
	}
	if n := integrationCount(t, client, "SELECT count() FROM system.columns WHERE database = currentDatabase() AND table = 'events' AND name = 'request_id'"); n != 1 {
		t.Error("events.request_id column missing")
	}

	// Idempotent.
	if err := m.Run(ctx); err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	applied, err := m.GetAppliedMigrations(ctx)
	if err != nil {
		t.Fatalf("GetAppliedMigrations() error = %v", err)
	}
	if len(applied) != 6 {
		t.Errorf("applied migrations = %v, want 6", applied)
	}

	// Retention TTLs apply on DateTime64 columns.
	r := NewRetentionManager(client, RetentionConfig{EventsTTL: 30 * 24 * time.Hour, QuarantineTTL: 7 * 24 * time.Hour})
	if err := r.ApplyTTLs(ctx); err != nil {
		t.Fatalf("ApplyTTLs() error = %v", err)
	}
	if n := integrationCount(t, client, "SELECT count() FROM system.tables WHERE database = currentDatabase() AND name = 'events' AND position(engine_full, 'toIntervalDay(30)') > 0"); n != 1 {
		t.Error("events TTL was not changed to 30 days")
	}
}

// H01 repair path: a database migrated by the old migrator has 001-005
// recorded but no tables.
func TestIntegrationRepairsBogusMigrationHistory(t *testing.T) {
	cfg := integrationConfig(t)
	ctx := context.Background()

	client, err := NewClickHouseClient(cfg)
	if err != nil {
		t.Fatalf("NewClickHouseClient() error = %v", err)
	}
	defer client.Close()

	m := NewMigrator(client)
	if err := m.createMigrationsTable(ctx); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for v := 1; v <= 5; v++ {
		if err := m.recordMigration(ctx, v, "bogus"); err != nil {
			t.Fatalf("record bogus migration: %v", err)
		}
	}

	if err := m.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := integrationTables(t, client); strings.Join(got, ",") != strings.Join(integrationSchema, ",") {
		t.Errorf("tables = %v, want %v", got, integrationSchema)
	}
	if n := integrationCount(t, client, "SELECT count() FROM schema_migrations"); n != 6 {
		t.Errorf("schema_migrations has %d rows, want 6 (repaired versions not recorded twice)", n)
	}
}

func integrationEvent(tenant string, i int) *schema.Event {
	now := time.Now().UTC()
	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     now.Add(-time.Duration(i) * time.Second),
		ReceivedAt:    now,
		Source:        schema.Source{Product: "it-product", Host: "10.1.2.3", InstanceID: "inst-1", Version: "1.0"},
		Actor:         &schema.Actor{Type: schema.ActorUser, ID: "000123", Name: "voilà", Email: "a@example.com", IPAddress: "192.0.2.10"},
		Action:        "auth.login",
		Target:        "host-1",
		Outcome:       schema.OutcomeSuccess,
		Severity:      1 + i%10,
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      tenant,
		RequestID:     "req-1",
		Raw:           `{"i":` + fmt.Sprint(i) + `}`,
		Metadata:      map[string]any{"device_vendor": "Acme"},
	}
}

func TestIntegrationBatchWriterAndQuarantine(t *testing.T) {
	cfg := integrationConfig(t)
	ctx := context.Background()

	client, err := NewClickHouseClient(cfg)
	if err != nil {
		t.Fatalf("NewClickHouseClient() error = %v", err)
	}
	defer client.Close()
	if err := NewMigrator(client).Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	qw := NewQuarantineWriter(client)
	bw := NewBatchWriter(client, BatchWriterConfig{BatchSize: 7, FlushInterval: 10 * time.Millisecond, MaxRetries: 1, RetryDelay: time.Millisecond},
		WithDeadLetter(qw.DeadLetter))
	for i := 0; i < 20; i++ {
		tenant := ""
		if i%4 == 0 {
			tenant = "t2"
		}
		if err := bw.Write(integrationEvent(tenant, i)); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if m := bw.Metrics(); m.Written != 20 || m.Failed != 0 {
		t.Errorf("metrics = %+v, want 20 written", m)
	}
	if n := integrationCount(t, client, "SELECT count() FROM events WHERE tenant_id = ?", DefaultTenantID); n != 15 {
		t.Errorf("default-tenant events = %d, want 15", n)
	}
	if n := integrationCount(t, client, "SELECT count() FROM events WHERE tenant_id = 't2'"); n != 5 {
		t.Errorf("t2 events = %d, want 5", n)
	}
	if n := integrationCount(t, client, "SELECT count() FROM events_critical"); n != 6 {
		t.Errorf("events_critical rows = %d, want 6 (severity >= 8)", n)
	}

	// Rejected-event quarantine (R21) and the dead-letter sink.
	if err := qw.Write(ctx, NewQuarantineEntry(`{"severity":99}`, "192.0.2.1", QuarantineFormatJSON, QuarantineCodeValidationFailed, "severity: out of range", "action: required")); err != nil {
		t.Fatalf("quarantine Write() error = %v", err)
	}
	if err := qw.WriteBatch(ctx, []*QuarantineEntry{
		NewQuarantineEntry("CEF:0|broken", "192.0.2.2", QuarantineFormatCEF, QuarantineCodeParseFailed),
	}); err != nil {
		t.Fatalf("quarantine WriteBatch() error = %v", err)
	}
	if err := qw.DeadLetter(ctx, []*schema.Event{integrationEvent("", 1)}, errors.New("insert failed")); err != nil {
		t.Fatalf("DeadLetter() error = %v", err)
	}
	count, err := qw.Count(ctx)
	if err != nil || count != 3 {
		t.Fatalf("quarantine Count() = %d, %v, want 3", count, err)
	}
	pending, err := qw.GetPendingReprocess(ctx, 10)
	if err != nil {
		t.Fatalf("GetPendingReprocess() error = %v", err)
	}
	codes := map[string][]string{}
	for _, p := range pending {
		codes[p.ErrorCode] = p.ValidationErrors
	}
	if len(codes[QuarantineCodeValidationFailed]) != 2 || codes[QuarantineCodeStorageFailed] == nil {
		t.Errorf("quarantined error codes = %v", codes)
	}
	if _, ok := codes[QuarantineCodeParseFailed]; !ok {
		t.Errorf("parse_failed entry missing: %v", codes)
	}
}
