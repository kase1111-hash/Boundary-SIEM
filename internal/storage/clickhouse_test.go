package storage

import (
	"errors"
	"fmt"
	"testing"

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

	cfg := DefaultClickHouseConfig()
	cfg.Database = "siem; DROP DATABASE other"
	if _, err := NewClickHouseClient(cfg); !errors.Is(err, ErrInvalidData) {
		t.Errorf("NewClickHouseClient with hostile database name error = %v, want ErrInvalidData", err)
	}

	c := newMockClient(&mockConn{})
	c.config.Database = "bad-name"
	if err := c.EnsureDatabase(t.Context()); !errors.Is(err, ErrInvalidData) {
		t.Errorf("EnsureDatabase with invalid name error = %v, want ErrInvalidData", err)
	}
}
