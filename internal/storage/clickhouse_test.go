package storage

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

func TestIsUnknownDatabase(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "unknown database", err: &clickhouse.Exception{Code: 81, Message: "Database siem does not exist"}, want: true},
		{name: "wrapped", err: fmt.Errorf("handshake: %w", &clickhouse.Exception{Code: 81}), want: true},
		{name: "other exception", err: &clickhouse.Exception{Code: 516, Message: "authentication failed"}},
		{name: "plain error", err: errors.New("connection refused")},
		{name: "nil", err: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isUnknownDatabase(tt.err); got != tt.want {
				t.Errorf("isUnknownDatabase(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestDatabaseNameValidation(t *testing.T) {
	for _, name := range []string{"siem", "siem_it_123", "_x", "SIEM"} {
		if !validIdentifier.MatchString(name) {
			t.Errorf("%q rejected, want accepted", name)
		}
	}
	for _, name := range []string{"", "1siem", "siem-prod", "siem;DROP DATABASE x", "si`em", "a b"} {
		if validIdentifier.MatchString(name) {
			t.Errorf("%q accepted, want rejected", name)
		}
	}

	if got := createDatabaseSQL("siem"); got != "CREATE DATABASE IF NOT EXISTS `siem`" {
		t.Errorf("createDatabaseSQL = %q", got)
	}

	// Automatic creation refuses such names before connecting anywhere.
	cfg := DefaultClickHouseConfig()
	cfg.Hosts = []string{"127.0.0.1:1"}
	cfg.Database = "siem; DROP DATABASE other"
	if err := createDatabase(t.Context(), cfg); !errors.Is(err, ErrInvalidData) {
		t.Errorf("createDatabase with hostile database name error = %v, want ErrInvalidData", err)
	}

	c := newMockClient(&mockConn{})
	c.config.Database = "bad-name"
	if err := c.EnsureDatabase(t.Context()); !errors.Is(err, ErrInvalidData) {
		t.Errorf("EnsureDatabase with invalid name error = %v, want ErrInvalidData", err)
	}
}

// Review regression: the name check only guards CREATE DATABASE. Connecting to
// an existing database is not restricted by it (the name travels in the
// handshake, not in SQL), so deployments using e.g. "siem-prod" keep working.
// Here the connection itself fails, so the error must be the connection error
// rather than an up-front ErrInvalidData.
func TestNewClickHouseClientDoesNotRejectExistingDatabaseNames(t *testing.T) {
	cfg := DefaultClickHouseConfig()
	cfg.Hosts = []string{"127.0.0.1:1"} // nothing listens here
	cfg.DialTimeout = 200 * time.Millisecond
	cfg.Database = "siem-prod"

	_, err := NewClickHouseClient(cfg)
	if err == nil {
		t.Fatal("NewClickHouseClient() to a closed port succeeded")
	}
	if errors.Is(err, ErrInvalidData) || !IsConnectionError(err) {
		t.Errorf("NewClickHouseClient(%q) error = %v, want a connection error", cfg.Database, err)
	}
}
