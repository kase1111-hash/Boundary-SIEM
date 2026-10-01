package storage

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Regression (R06): "ALTER TABLE ... MODIFY TTL timestamp + INTERVAL ..." is
// rejected by ClickHouse 23.8/24.8 because the columns are DateTime64, so the
// configured retention was never applied there.
func TestRetentionApplyTTLsConvertsToDateTime(t *testing.T) {
	conn := &migrationConn{}
	r := NewRetentionManager(newMockClient(conn), RetentionConfig{
		EventsTTL:     30 * 24 * time.Hour,
		CriticalTTL:   400 * 24 * time.Hour,
		QuarantineTTL: 7 * 24 * time.Hour,
		AlertsTTL:     time.Hour, // rounds up to one day
	})

	if err := r.ApplyTTLs(context.Background()); err != nil {
		t.Fatalf("ApplyTTLs() error = %v", err)
	}

	want := []string{
		"ALTER TABLE events MODIFY TTL toDateTime(timestamp) + INTERVAL 30 DAY DELETE",
		"ALTER TABLE events_critical MODIFY TTL toDateTime(timestamp) + INTERVAL 400 DAY DELETE",
		"ALTER TABLE events_quarantine MODIFY TTL toDateTime(quarantined_at) + INTERVAL 7 DAY DELETE",
		"ALTER TABLE alerts MODIFY TTL toDateTime(created_at) + INTERVAL 1 DAY DELETE",
	}
	got := conn.executed()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("executed:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
