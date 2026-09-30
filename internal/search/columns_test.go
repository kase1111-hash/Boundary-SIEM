package search

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// migrationsDir holds the ClickHouse schema the executor queries.
const migrationsDir = "../storage/migrations"

// eventsTableColumns returns the columns of the events table as defined by
// the CREATE TABLE and ALTER TABLE ... ADD COLUMN statements in the
// migrations.
func eventsTableColumns(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations found in %s: %v", migrationsDir, err)
	}
	sort.Strings(files)

	createEvents := regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?events\s*\((.*?)\n\)\s*ENGINE`)
	columnDef := regexp.MustCompile(`^\s*([a-z_][a-z0-9_]*)\s+[A-Z]`)
	addColumn := regexp.MustCompile(`(?i)ALTER\s+TABLE\s+events\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)

	columns := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		sql := string(data)
		if m := createEvents.FindStringSubmatch(sql); m != nil {
			for _, line := range strings.Split(m[1], "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "--") || strings.HasPrefix(line, "INDEX ") {
					continue
				}
				if c := columnDef.FindStringSubmatch(line); c != nil {
					columns[c[1]] = true
				}
			}
		}
		for _, m := range addColumn.FindAllStringSubmatch(sql, -1) {
			columns[m[1]] = true
		}
	}
	if !columns["event_id"] || !columns["tenant_id"] || !columns["request_id"] {
		t.Fatalf("parsed events columns look wrong: %v", columns)
	}
	return columns
}

// Regression (R03): Search and GetEvent selected source_vendor and
// source_ip, and the allowlist and field mapping pointed at source_vendor,
// source_hostname and source_ip. None of them exist, so every search failed
// in ClickHouse with "Unknown expression identifier".
func TestEventColumnsExistInMigrations(t *testing.T) {
	columns := eventsTableColumns(t)
	check := func(where, column string) {
		t.Helper()
		if !columns[column] {
			t.Errorf("%s references %q, which is not a column of the events table", where, column)
		}
	}

	for _, c := range strings.Split(eventColumns, ",") {
		check("Search/GetEvent projection", strings.TrimSpace(c))
	}
	for k, v := range validColumns {
		check("validColumns key", k)
		check("validColumns value", v)
	}
	for _, v := range validOrderByColumns {
		check("validOrderByColumns", v)
	}
	for field, col := range FieldMapping {
		if strings.HasPrefix(col, "metadata.") {
			continue
		}
		check("FieldMapping["+field+"]", col)
	}
}

// The projection must match what BatchWriter inserts, so that every stored
// field can be read back.
func TestEventColumnsCoverInsertedColumns(t *testing.T) {
	projected := map[string]bool{}
	for _, c := range strings.Split(eventColumns, ",") {
		projected[strings.TrimSpace(c)] = true
	}
	for c := range eventsTableColumns(t) {
		if !projected[c] {
			t.Errorf("events column %q is not returned by Search/GetEvent", c)
		}
	}
}
