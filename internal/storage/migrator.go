package storage

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migration represents a database migration.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// Migrator handles database migrations.
//
// Every statement in a migration must be idempotent (CREATE ... IF NOT
// EXISTS, ALTER ... ADD ... IF NOT EXISTS, ...). A migration is recorded only
// after all of its statements succeed, so a partially applied migration is
// re-run from the start; the migrator also re-runs recorded migrations whose
// tables are missing (see Run).
type Migrator struct {
	client *ClickHouseClient
}

// NewMigrator creates a new Migrator.
func NewMigrator(client *ClickHouseClient) *Migrator {
	return &Migrator{client: client}
}

// noRepair is the sentinel returned by firstIncompleteMigration when every
// recorded migration's tables exist.
const noRepair = math.MaxInt

// Run executes all pending migrations.
//
// Recorded migrations are normally skipped. If a recorded migration created a
// table or view that the final schema should contain but the database lacks
// it, that migration and every later one are applied again. This repairs
// databases where earlier releases recorded migrations as applied without
// executing them (their statements were skipped because they started with a
// comment). Re-applied migrations are not recorded a second time.
func (m *Migrator) Run(ctx context.Context) error {
	// Create migrations tracking table
	if err := m.createMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Load migrations
	migrations, err := m.loadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	// Get applied migrations
	applied, err := m.getAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	reapplyFrom, err := m.firstIncompleteMigration(ctx, migrations, applied)
	if err != nil {
		return fmt.Errorf("failed to verify applied migrations: %w", err)
	}

	// Run pending migrations
	for _, migration := range migrations {
		recorded := applied[migration.Version]
		if recorded && migration.Version < reapplyFrom {
			slog.Debug("migration already applied",
				"version", migration.Version,
				"name", migration.Name,
			)
			continue
		}

		if recorded {
			slog.Warn("re-applying migration recorded as applied because the schema it creates is missing",
				"version", migration.Version,
				"name", migration.Name,
			)
		} else {
			slog.Info("applying migration",
				"version", migration.Version,
				"name", migration.Name,
			)
		}

		for _, stmt := range splitStatements(migration.SQL) {
			if err := m.client.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("failed to apply migration %d (%s): %w",
					migration.Version, migration.Name, err)
			}
		}

		if !recorded {
			if err := m.recordMigration(ctx, migration.Version, migration.Name); err != nil {
				return fmt.Errorf("failed to record migration %d: %w", migration.Version, err)
			}
		}

		slog.Info("migration applied",
			"version", migration.Version,
			"name", migration.Name,
		)
	}

	return nil
}

// createMigrationsTable creates the schema_migrations table if it doesn't exist.
func (m *Migrator) createMigrationsTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version UInt32,
			name String,
			applied_at DateTime DEFAULT now()
		)
		ENGINE = MergeTree()
		ORDER BY version
	`
	return m.client.Exec(ctx, query)
}

// loadMigrations loads all migration files.
func (m *Migrator) loadMigrations() ([]Migration, error) {
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return nil, err
	}

	var migrations []Migration
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		content, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, err
		}

		// Parse version from filename (e.g., 001_create_events.sql)
		var version int
		var name string
		_, err = fmt.Sscanf(entry.Name(), "%03d_%s", &version, &name)
		if err != nil {
			continue
		}
		name = strings.TrimSuffix(name, ".sql")

		migrations = append(migrations, Migration{
			Version: version,
			Name:    name,
			SQL:     string(content),
		})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// getAppliedMigrations returns a map of applied migration versions.
func (m *Migrator) getAppliedMigrations(ctx context.Context) (map[int]bool, error) {
	rows, err := m.client.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var version uint32
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[int(version)] = true
	}

	return applied, rows.Err()
}

// firstIncompleteMigration returns the lowest recorded migration version
// that created a table or view which the final schema should contain but the
// database does not, or noRepair when there is none.
func (m *Migrator) firstIncompleteMigration(ctx context.Context, migrations []Migration, applied map[int]bool) (int, error) {
	if len(applied) == 0 {
		return noRepair, nil
	}

	expected := finalSchemaObjects(migrations)
	existing, err := m.existingTables(ctx)
	if err != nil {
		return 0, err
	}

	first := noRepair
	for _, migration := range migrations {
		if !applied[migration.Version] || migration.Version >= first {
			continue
		}
		for _, stmt := range splitStatements(migration.SQL) {
			name, ok := createdObject(stmt)
			if ok && expected[name] && !existing[name] {
				first = migration.Version
				break
			}
		}
	}
	return first, nil
}

// existingTables returns the tables and views in the connection's database.
func (m *Migrator) existingTables(ctx context.Context) (map[string]bool, error) {
	rows, err := m.client.Query(ctx, "SELECT name FROM system.tables WHERE database = currentDatabase()")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tables := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables[name] = true
	}
	return tables, rows.Err()
}

var (
	createObjectPattern = regexp.MustCompile("(?is)^CREATE\\s+(?:OR\\s+REPLACE\\s+)?(?:TABLE|MATERIALIZED\\s+VIEW|VIEW|DICTIONARY)\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?([`\"\\w.]+)")
	dropObjectPattern   = regexp.MustCompile("(?is)^DROP\\s+(?:TABLE|VIEW|DICTIONARY)\\s+(?:IF\\s+EXISTS\\s+)?([`\"\\w.]+)")
)

// createdObject returns the table, view or dictionary a CREATE statement creates.
func createdObject(stmt string) (string, bool) {
	match := createObjectPattern.FindStringSubmatch(stmt)
	if match == nil {
		return "", false
	}
	return unqualifiedName(match[1]), true
}

// droppedObject returns the table, view or dictionary a DROP statement removes.
func droppedObject(stmt string) (string, bool) {
	match := dropObjectPattern.FindStringSubmatch(stmt)
	if match == nil {
		return "", false
	}
	return unqualifiedName(match[1]), true
}

// unqualifiedName strips identifier quotes and a database prefix.
func unqualifiedName(name string) string {
	name = strings.NewReplacer("`", "", `"`, "").Replace(name)
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// finalSchemaObjects returns the tables, views and dictionaries that exist
// after applying every migration in order.
func finalSchemaObjects(migrations []Migration) map[string]bool {
	objects := make(map[string]bool)
	for _, migration := range migrations {
		for _, stmt := range splitStatements(migration.SQL) {
			if name, ok := createdObject(stmt); ok {
				objects[name] = true
			} else if name, ok := droppedObject(stmt); ok {
				delete(objects, name)
			}
		}
	}
	return objects
}

// recordMigration records a migration as applied.
func (m *Migrator) recordMigration(ctx context.Context, version int, name string) error {
	v, err := migrationVersionToUInt32(version)
	if err != nil {
		return err
	}
	return m.client.Exec(ctx,
		"INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
		v, name,
	)
}

// migrationVersionToUInt32 converts a migration version to the UInt32
// schema_migrations.version column, rejecting values that would not fit.
func migrationVersionToUInt32(version int) (uint32, error) {
	if version < 0 || int64(version) > math.MaxUint32 {
		return 0, fmt.Errorf("migration version %d out of range for schema_migrations.version (UInt32)", version)
	}
	return uint32(version), nil
}

// splitStatements splits SQL content into individual statements.
//
// Statements are separated by semicolons outside string literals and quoted
// identifiers. "--" line comments and "/* */" block comments outside quotes
// are removed, so a returned statement never starts with a comment and a
// semicolon inside a comment does not end a statement. Quoted text is copied
// verbatim; inside quotes, a quote character is escaped either by doubling
// it or with a preceding backslash. Statements that are empty once comments are
// removed are dropped.
func splitStatements(sql string) []string {
	var statements []string
	var current strings.Builder

	flush := func() {
		if stmt := strings.TrimSpace(current.String()); stmt != "" {
			statements = append(statements, stmt)
		}
		current.Reset()
	}

	for i := 0; i < len(sql); i++ {
		c := sql[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			end := quotedEnd(sql, i)
			current.WriteString(sql[i:end])
			i = end - 1

		case c == '-' && i+1 < len(sql) && sql[i+1] == '-':
			// Line comment: skip up to (not including) the newline so the
			// tokens on either side stay separated.
			nl := strings.IndexByte(sql[i:], '\n')
			if nl < 0 {
				i = len(sql)
			} else {
				i += nl - 1
			}

		case c == '/' && i+1 < len(sql) && sql[i+1] == '*':
			current.WriteByte(' ')
			closeIdx := strings.Index(sql[i+2:], "*/")
			if closeIdx < 0 {
				i = len(sql)
			} else {
				i += 2 + closeIdx + 1
			}

		case c == ';':
			flush()

		default:
			current.WriteByte(c)
		}
	}
	flush()

	return statements
}

// quotedEnd returns the index just past the quoted section that starts at
// sql[start], or len(sql) when the quote is never closed.
func quotedEnd(sql string, start int) int {
	quote := sql[start]
	for j := start + 1; j < len(sql); j++ {
		switch sql[j] {
		case '\\':
			j++ // skip the escaped character
		case quote:
			if j+1 < len(sql) && sql[j+1] == quote {
				j++ // doubled quote is an escaped quote
				continue
			}
			return j + 1
		}
	}
	return len(sql)
}

// GetAppliedMigrations returns the list of applied migrations.
func (m *Migrator) GetAppliedMigrations(ctx context.Context) ([]Migration, error) {
	rows, err := m.client.Query(ctx, "SELECT version, name FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var migrations []Migration
	for rows.Next() {
		var version uint32
		var name string
		if err := rows.Scan(&version, &name); err != nil {
			return nil, err
		}
		migrations = append(migrations, Migration{
			Version: int(version),
			Name:    name,
		})
	}

	return migrations, rows.Err()
}
