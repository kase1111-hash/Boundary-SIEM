package storage

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// Schema fixups are changes to an existing schema that a SQL migration
// cannot express: one needs a table name known only at run time, the other
// must run only while the schema is in a given state (a SQL migration's
// statements must each be idempotent, see Migrator). Migrator.Run applies
// them after the SQL migrations, every time; each checks the schema first
// and changes nothing when it is already right.

// schemaFixup is one such change. apply reports whether it changed the
// schema.
type schemaFixup struct {
	name  string
	apply func(ctx context.Context, m *Migrator) (bool, error)
}

var schemaFixups = []schemaFixup{
	{name: "deduplication window of materialized view inner tables", apply: fixInnerTableDedupWindows},
	{name: "alerts sorting key without status", apply: fixAlertsSortingKey},
}

// runSchemaFixups applies every schema fixup.
func (m *Migrator) runSchemaFixups(ctx context.Context) error {
	for _, fixup := range schemaFixups {
		changed, err := fixup.apply(ctx, m)
		if err != nil {
			return fmt.Errorf("schema fixup %q: %w", fixup.name, err)
		}
		if changed {
			slog.Info("schema fixup applied", "fixup", fixup.name)
		}
	}
	return nil
}

// dedupWindowBlocks is the non_replicated_deduplication_window of the tables
// written by event inserts (see migration 007).
const dedupWindowBlocks = 1000

// innerTableName matches the inner table of a materialized view created
// with an ENGINE: .inner_id.<uuid> in an Atomic database, .inner.<view> in
// an Ordinary one. Only such names are put into ALTER statements.
var innerTableName = regexp.MustCompile(`^\.inner(_id)?\.[0-9A-Za-z_.-]+$`)

// innerTablesWithoutDedupWindow lists the non-replicated MergeTree inner
// tables of materialized views that keep no deduplication window.
const innerTablesWithoutDedupWindow = `SELECT name FROM system.tables
WHERE database = currentDatabase()
  AND startsWith(name, '.inner')
  AND endsWith(engine, 'MergeTree') AND NOT startsWith(engine, 'Replicated')
  AND position(engine_full, 'non_replicated_deduplication_window') = 0`

// fixInnerTableDedupWindows gives the inner table of events_hourly_mv (and
// of any other view created with an ENGINE) the deduplication window of
// migration 007.
//
// The batch writer retries an INSERT whose outcome is unknown under the same
// insert_deduplication_token, with deduplicate_blocks_in_dependent_
// materialized_views, so events and events_critical store a repeat once.
// The SummingMergeTree inside events_hourly_mv kept no window, so it counted
// every repeat again (13000 hourly events for 10000 stored). Its name is
// generated (.inner_id.<uuid>), and ALTER on the view itself cannot change
// the inner table's settings, so no SQL migration can set it.
func fixInnerTableDedupWindows(ctx context.Context, m *Migrator) (bool, error) {
	names, err := m.queryStrings(ctx, innerTablesWithoutDedupWindow)
	if err != nil {
		return false, err
	}
	changed := false
	for _, name := range names {
		if !innerTableName.MatchString(name) {
			slog.Warn("not setting the deduplication window of an inner table with an unexpected name", "table", name)
			continue
		}
		stmt := fmt.Sprintf("ALTER TABLE `%s` MODIFY SETTING non_replicated_deduplication_window = %d", name, dedupWindowBlocks)
		if err := m.client.Exec(ctx, stmt); err != nil {
			return changed, fmt.Errorf("set the deduplication window of %s: %w", name, err)
		}
		changed = true
	}
	return changed, nil
}

// alertsRebuildTable is where fixAlertsSortingKey builds the new alerts table.
const alertsRebuildTable = "alerts_v2"

// alertsRebuild rebuilds alerts with the sorting key (tenant_id, created_at,
// alert_id). The first statement removes what an interrupted rebuild left;
// alerts_v2 never holds the only copy of the alerts, since EXCHANGE swaps
// the tables atomically (it needs the Atomic database engine, the default
// since ClickHouse 20.10).
var alertsRebuild = []string{
	"DROP TABLE IF EXISTS " + alertsRebuildTable,
	`CREATE TABLE ` + alertsRebuildTable + ` (
    alert_id UUID,
    tenant_id LowCardinality(String) DEFAULT '',
    rule_id String,
    rule_name String,
    rule_type LowCardinality(String),
    severity LowCardinality(String),
    title String,
    description String,
    status LowCardinality(String) DEFAULT 'open',
    created_at DateTime64(6, 'UTC'),
    updated_at DateTime64(6, 'UTC'),
    acknowledged_at Nullable(DateTime64(6, 'UTC')),
    resolved_at Nullable(DateTime64(6, 'UTC')),
    acknowledged_by String DEFAULT '',
    resolved_by String DEFAULT '',
    assignee String DEFAULT '',
    group_key String DEFAULT '',
    event_count UInt32 DEFAULT 0,
    sample_event_ids Array(String),
    metadata String CODEC(ZSTD(3)),
    notes String CODEC(ZSTD(3)),
    INDEX idx_alert_rule_id rule_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_alert_status status TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_alert_severity severity TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_alert_assignee assignee TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(created_at)
ORDER BY (tenant_id, created_at, alert_id)
TTL toDateTime(created_at) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192`,
	`INSERT INTO ` + alertsRebuildTable + ` (` + alertsColumns + `) SELECT ` + alertsColumns + ` FROM alerts`,
	"EXCHANGE TABLES alerts AND " + alertsRebuildTable,
	"DROP TABLE " + alertsRebuildTable,
}

// alertsColumns are the columns of the alerts table.
const alertsColumns = `alert_id, tenant_id, rule_id, rule_name, rule_type, severity, title, description, status,
    created_at, updated_at, acknowledged_at, resolved_at, acknowledged_by, resolved_by, assignee,
    group_key, event_count, sample_event_ids, metadata, notes`

// fixAlertsSortingKey rebuilds an alerts table whose sorting key contains
// status (migration 004).
//
// Every update of an alert (acknowledge, assign, resolve, a merged
// recurrence) inserts a new version of its row, and the ReplacingMergeTree
// is meant to keep the latest. With status in the sorting key, versions with
// different statuses had different keys, so they were never collapsed: the
// table grew with every update and FINAL returned one row per status the
// alert ever held. A sorting key cannot drop a column in place.
func fixAlertsSortingKey(ctx context.Context, m *Migrator) (bool, error) {
	keys, err := m.queryStrings(ctx, "SELECT sorting_key FROM system.tables WHERE database = currentDatabase() AND name = 'alerts'")
	if err != nil || len(keys) == 0 {
		return false, err // no alerts table: nothing to fix
	}
	if !sortingKeyHas(keys[0], "status") {
		// A rebuild interrupted after the swap leaves the old table behind.
		existing, err := m.existingTables(ctx)
		if err != nil || !existing[alertsRebuildTable] {
			return false, err
		}
		return true, m.client.Exec(ctx, "DROP TABLE "+alertsRebuildTable)
	}
	for _, stmt := range alertsRebuild {
		if err := m.client.Exec(ctx, stmt); err != nil {
			return false, fmt.Errorf("rebuild alerts: %w", err)
		}
	}
	return true, nil
}

// sortingKeyHas reports whether the sorting key expression key (as
// system.tables.sorting_key shows it, "a, b, c") has the column column.
func sortingKeyHas(key, column string) bool {
	for part := range strings.SplitSeq(key, ",") {
		if strings.TrimSpace(part) == column {
			return true
		}
	}
	return false
}

// queryStrings runs a query returning one String column.
func (m *Migrator) queryStrings(ctx context.Context, query string) ([]string, error) {
	rows, err := m.client.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
