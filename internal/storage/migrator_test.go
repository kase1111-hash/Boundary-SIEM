package storage

import (
	"testing"
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
			name: "statement with semicolon in string",
			sql:  "INSERT INTO t VALUES ('hello; world')",
			expected: []string{"INSERT INTO t VALUES ('hello; world')"},
		},
		{
			name: "multiple with comments",
			sql: `-- Comment
CREATE TABLE a (id INT);
-- Another comment
CREATE TABLE b (id INT)`,
			expected: []string{"-- Comment\nCREATE TABLE a (id INT)", "-- Another comment\nCREATE TABLE b (id INT)"},
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
