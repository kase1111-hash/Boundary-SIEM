// Package storage provides ClickHouse storage for SIEM events.
package storage

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
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
	sqlDB  *sql.DB
	config ClickHouseConfig
}

// NewClickHouseClient creates a new ClickHouse client.
//
// If the configured database does not exist yet it is created (CREATE
// DATABASE IF NOT EXISTS, through a connection to the server's default
// database), so a fresh server needs no manual setup before migrations run.
// Only names matching validIdentifier are created automatically; an existing
// database may have any name, since the name is only sent in the connection
// handshake and never embedded in SQL.
func NewClickHouseClient(cfg ClickHouseConfig) (*ClickHouseClient, error) {
	opts := clickHouseOptions(cfg)

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, WrapConnectionError("Open", err)
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout(cfg))
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		if !isUnknownDatabase(err) {
			_ = conn.Close()
			return nil, WrapConnectionError("Ping", err)
		}
		slog.Info("ClickHouse database does not exist, creating it", "database", cfg.Database)
		if err := createDatabase(ctx, cfg); err != nil {
			_ = conn.Close()
			if errors.Is(err, ErrInvalidData) {
				return nil, err
			}
			return nil, WrapConnectionError("CreateDatabase", err)
		}
		if err := conn.Ping(ctx); err != nil {
			_ = conn.Close()
			return nil, WrapConnectionError("Ping", err)
		}
	}

	// Also create a database/sql compatible connection for search queries
	sqlDB := clickhouse.OpenDB(opts)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	return &ClickHouseClient{
		conn:   conn,
		sqlDB:  sqlDB,
		config: cfg,
	}, nil
}

// clickHouseOptions builds the driver options for cfg.
func clickHouseOptions(cfg ClickHouseConfig) *clickhouse.Options {
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
	}

	if cfg.Debug {
		// Driver debug logging to stdout; replaces the deprecated Options.Debug.
		opts.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	if cfg.TLSEnabled {
		opts.TLS = &tls.Config{
			InsecureSkipVerify: false,
		}
	}

	return opts
}

// connectTimeout bounds the initial ping and database bootstrap.
func connectTimeout(cfg ClickHouseConfig) time.Duration {
	if cfg.DialTimeout > 5*time.Second {
		return cfg.DialTimeout
	}
	return 5 * time.Second
}

// codeUnknownDatabase is ClickHouse's UNKNOWN_DATABASE error code.
const codeUnknownDatabase = 81

// isUnknownDatabase reports whether err is ClickHouse's "Database ... does
// not exist" error.
func isUnknownDatabase(err error) bool {
	var ex *clickhouse.Exception
	return errors.As(err, &ex) && ex.Code == codeUnknownDatabase
}

// createDatabase creates cfg.Database through a short-lived connection to the
// server's default database. It refuses names that do not match
// validIdentifier (ErrInvalidData) without connecting.
func createDatabase(ctx context.Context, cfg ClickHouseConfig) error {
	if !validIdentifier.MatchString(cfg.Database) {
		return fmt.Errorf("%w: ClickHouse database %q does not exist and is not created automatically "+
			"(only names matching %s are); create it manually", ErrInvalidData, cfg.Database, validIdentifier)
	}

	bootstrap := cfg
	bootstrap.Database = ""
	bootstrap.MaxOpenConns = 1
	bootstrap.MaxIdleConns = 1

	conn, err := clickhouse.Open(clickHouseOptions(bootstrap))
	if err != nil {
		return err
	}
	defer conn.Close()

	return conn.Exec(ctx, createDatabaseSQL(cfg.Database))
}

// validIdentifier matches database names that are safe to embed in DDL.
var validIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// createDatabaseSQL returns the CREATE DATABASE statement for name, which the
// caller has checked against validIdentifier.
func createDatabaseSQL(name string) string {
	return "CREATE DATABASE IF NOT EXISTS `" + name + "`"
}

// Close closes the ClickHouse connection.
func (c *ClickHouseClient) Close() error {
	if c.sqlDB != nil {
		c.sqlDB.Close()
	}
	return c.conn.Close()
}

// DB returns the database/sql compatible connection.
// This is used by the search package for query execution.
func (c *ClickHouseClient) DB() *sql.DB {
	return c.sqlDB
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
// NewClickHouseClient already does this when the database is missing.
func (c *ClickHouseClient) EnsureDatabase(ctx context.Context) error {
	if !validIdentifier.MatchString(c.config.Database) {
		return fmt.Errorf("%w: invalid ClickHouse database name %q", ErrInvalidData, c.config.Database)
	}
	return c.conn.Exec(ctx, createDatabaseSQL(c.config.Database))
}
