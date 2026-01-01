// Package storage provides ClickHouse storage for SIEM events.
package storage

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// ClickHouseConfig holds the configuration for ClickHouse connection.
type ClickHouseConfig struct {
	Hosts           []string      `yaml:"hosts"`
	Database        string        `yaml:"database"`
	Username        string        `yaml:"username"`
	Password        string        `yaml:"password"`
	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
	TLSEnabled      bool          `yaml:"tls_enabled"`
	DialTimeout     time.Duration `yaml:"dial_timeout"`
	Debug           bool          `yaml:"debug"`
}

// DefaultClickHouseConfig returns the default ClickHouse configuration.
func DefaultClickHouseConfig() ClickHouseConfig {
	return ClickHouseConfig{
		Hosts:           []string{"localhost:9000"},
		Database:        "siem",
		Username:        "default",
		Password:        "",
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
		TLSEnabled:      false,
		DialTimeout:     10 * time.Second,
		Debug:           false,
	}
}

// ClickHouseClient wraps the ClickHouse connection.
type ClickHouseClient struct {
	conn   driver.Conn
	config ClickHouseConfig
}

// NewClickHouseClient creates a new ClickHouse client.
func NewClickHouseClient(cfg ClickHouseConfig) (*ClickHouseClient, error) {
	opts := &clickhouse.Options{
		Addr: cfg.Hosts,
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionZSTD,
		},
		DialTimeout:     cfg.DialTimeout,
		MaxOpenConns:    cfg.MaxOpenConns,
		MaxIdleConns:    cfg.MaxIdleConns,
		ConnMaxLifetime: cfg.ConnMaxLifetime,
		Debug:           cfg.Debug,
	}

	if cfg.TLSEnabled {
		opts.TLS = &tls.Config{
			InsecureSkipVerify: false,
		}
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ClickHouse: %w", err)
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping ClickHouse: %w", err)
	}

	return &ClickHouseClient{
		conn:   conn,
		config: cfg,
	}, nil
}

// Close closes the ClickHouse connection.
func (c *ClickHouseClient) Close() error {
	return c.conn.Close()
}

// Ping checks if the connection is alive.
func (c *ClickHouseClient) Ping(ctx context.Context) error {
	return c.conn.Ping(ctx)
}

// Conn returns the underlying connection.
func (c *ClickHouseClient) Conn() driver.Conn {
	return c.conn
}

// Exec executes a query without returning rows.
func (c *ClickHouseClient) Exec(ctx context.Context, query string, args ...any) error {
	return c.conn.Exec(ctx, query, args...)
}

// Query executes a query and returns rows.
func (c *ClickHouseClient) Query(ctx context.Context, query string, args ...any) (driver.Rows, error) {
	return c.conn.Query(ctx, query, args...)
}

// PrepareBatch prepares a batch for insertion.
func (c *ClickHouseClient) PrepareBatch(ctx context.Context, query string) (driver.Batch, error) {
	return c.conn.PrepareBatch(ctx, query)
}

// Stats returns connection pool statistics.
func (c *ClickHouseClient) Stats() driver.Stats {
	return c.conn.Stats()
}

// Database returns the database name.
func (c *ClickHouseClient) Database() string {
	return c.config.Database
}

// EnsureDatabase creates the database if it doesn't exist.
func (c *ClickHouseClient) EnsureDatabase(ctx context.Context) error {
	query := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", c.config.Database)
	return c.conn.Exec(ctx, query)
}
