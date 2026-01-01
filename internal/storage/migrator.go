package storage

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
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
type Migrator struct {
	client *ClickHouseClient
}

// NewMigrator creates a new Migrator.
func NewMigrator(client *ClickHouseClient) *Migrator {
	return &Migrator{client: client}
}

// Run executes all pending migrations.
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

	// Run pending migrations
	for _, migration := range migrations {
		if applied[migration.Version] {
			slog.Debug("migration already applied",
				"version", migration.Version,
				"name", migration.Name,
			)
			continue
		}

		slog.Info("applying migration",
			"version", migration.Version,
			"name", migration.Name,
		)

		// Split SQL into individual statements
		statements := splitStatements(migration.SQL)
		for _, stmt := range statements {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" || strings.HasPrefix(stmt, "--") {
				continue
			}

			if err := m.client.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("failed to apply migration %d (%s): %w",
					migration.Version, migration.Name, err)
			}
		}

		if err := m.recordMigration(ctx, migration.Version, migration.Name); err != nil {
			return fmt.Errorf("failed to record migration %d: %w", migration.Version, err)
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

	return applied, nil
}

// recordMigration records a migration as applied.
func (m *Migrator) recordMigration(ctx context.Context, version int, name string) error {
	return m.client.Exec(ctx,
		"INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
		uint32(version), name,
	)
}

// splitStatements splits SQL content into individual statements.
func splitStatements(sql string) []string {
	var statements []string
	var current strings.Builder
	inString := false
	stringChar := rune(0)

	for i, char := range sql {
		if !inString {
			if char == '\'' || char == '"' {
				inString = true
				stringChar = char
			} else if char == ';' {
				stmt := strings.TrimSpace(current.String())
				if stmt != "" {
					statements = append(statements, stmt)
				}
				current.Reset()
				continue
			}
		} else {
			if char == stringChar {
				// Check for escaped quote
				if i+1 < len(sql) && rune(sql[i+1]) == stringChar {
					current.WriteRune(char)
					continue
				}
				inString = false
			}
		}
		current.WriteRune(char)
	}

	// Add any remaining content
	stmt := strings.TrimSpace(current.String())
	if stmt != "" {
		statements = append(statements, stmt)
	}

	return statements
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

	return migrations, nil
}
