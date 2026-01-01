// Package config handles configuration loading for Boundary-SIEM.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the complete application configuration.
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Ingest     IngestConfig     `yaml:"ingest"`
	Queue      QueueConfig      `yaml:"queue"`
	Validation ValidationConfig `yaml:"validation"`
	Auth       AuthConfig       `yaml:"auth"`
	Logging    LoggingConfig    `yaml:"logging"`
	Storage    StorageConfig    `yaml:"storage"`
	Consumer   ConsumerConfig   `yaml:"consumer"`
}

// StorageConfig holds storage settings.
type StorageConfig struct {
	Enabled     bool              `yaml:"enabled"`
	ClickHouse  ClickHouseConfig  `yaml:"clickhouse"`
	BatchWriter BatchWriterConfig `yaml:"batch_writer"`
}

// ClickHouseConfig holds ClickHouse connection settings.
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
}

// BatchWriterConfig holds batch writer settings.
type BatchWriterConfig struct {
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	MaxRetries    int           `yaml:"max_retries"`
	RetryDelay    time.Duration `yaml:"retry_delay"`
}

// ConsumerConfig holds consumer settings.
type ConsumerConfig struct {
	Workers      int           `yaml:"workers"`
	PollInterval time.Duration `yaml:"poll_interval"`
	ShutdownWait time.Duration `yaml:"shutdown_wait"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	HTTPPort     int           `yaml:"http_port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

// IngestConfig holds ingestion settings.
type IngestConfig struct {
	MaxBatchSize   int `yaml:"max_batch_size"`
	MaxPayloadSize int `yaml:"max_payload_size"`
}

// QueueConfig holds queue settings.
type QueueConfig struct {
	Size           int    `yaml:"size"`
	OverflowPolicy string `yaml:"overflow_policy"`
}

// ValidationConfig holds validation settings.
type ValidationConfig struct {
	MaxEventAge time.Duration `yaml:"max_event_age"`
	MaxFuture   time.Duration `yaml:"max_future"`
	StrictMode  bool          `yaml:"strict_mode"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	APIKeyHeader string   `yaml:"api_key_header"`
	APIKeys      []string `yaml:"api_keys"`
	Enabled      bool     `yaml:"enabled"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			HTTPPort:     8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Ingest: IngestConfig{
			MaxBatchSize:   1000,
			MaxPayloadSize: 10 * 1024 * 1024, // 10MB
		},
		Queue: QueueConfig{
			Size:           100000,
			OverflowPolicy: "reject",
		},
		Validation: ValidationConfig{
			MaxEventAge: 7 * 24 * time.Hour,
			MaxFuture:   5 * time.Minute,
			StrictMode:  true,
		},
		Auth: AuthConfig{
			APIKeyHeader: "X-API-Key",
			Enabled:      false, // Disabled by default for development
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		Storage: StorageConfig{
			Enabled: false, // Disabled by default for development without ClickHouse
			ClickHouse: ClickHouseConfig{
				Hosts:           []string{"localhost:9000"},
				Database:        "siem",
				Username:        "default",
				Password:        "",
				MaxOpenConns:    10,
				MaxIdleConns:    5,
				ConnMaxLifetime: time.Hour,
				TLSEnabled:      false,
				DialTimeout:     10 * time.Second,
			},
			BatchWriter: BatchWriterConfig{
				BatchSize:     1000,
				FlushInterval: 5 * time.Second,
				MaxRetries:    3,
				RetryDelay:    time.Second,
			},
		},
		Consumer: ConsumerConfig{
			Workers:      4,
			PollInterval: 10 * time.Millisecond,
			ShutdownWait: 30 * time.Second,
		},
	}
}

// Load loads configuration from a file or returns defaults.
func Load() (*Config, error) {
	cfg := DefaultConfig()

	// Check for config file path in environment
	configPath := os.Getenv("SIEM_CONFIG_PATH")
	if configPath == "" {
		configPath = "configs/config.yaml"
	}

	// Try to load from file
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, use defaults
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Override with environment variables
	cfg.applyEnvOverrides()

	return cfg, nil
}

// applyEnvOverrides applies environment variable overrides.
func (c *Config) applyEnvOverrides() {
	if port := os.Getenv("SIEM_HTTP_PORT"); port != "" {
		fmt.Sscanf(port, "%d", &c.Server.HTTPPort)
	}

	if level := os.Getenv("SIEM_LOG_LEVEL"); level != "" {
		c.Logging.Level = level
	}

	if apiKey := os.Getenv("SIEM_API_KEY"); apiKey != "" {
		c.Auth.APIKeys = append(c.Auth.APIKeys, apiKey)
		c.Auth.Enabled = true
	}

	// Storage settings
	if enabled := os.Getenv("SIEM_STORAGE_ENABLED"); enabled == "true" {
		c.Storage.Enabled = true
	}

	if host := os.Getenv("CLICKHOUSE_HOST"); host != "" {
		c.Storage.ClickHouse.Hosts = []string{host}
	}

	if db := os.Getenv("CLICKHOUSE_DATABASE"); db != "" {
		c.Storage.ClickHouse.Database = db
	}

	if user := os.Getenv("CLICKHOUSE_USER"); user != "" {
		c.Storage.ClickHouse.Username = user
	}

	if pass := os.Getenv("CLICKHOUSE_PASSWORD"); pass != "" {
		c.Storage.ClickHouse.Password = pass
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.Server.HTTPPort <= 0 || c.Server.HTTPPort > 65535 {
		return fmt.Errorf("invalid http_port: %d", c.Server.HTTPPort)
	}

	if c.Queue.Size <= 0 {
		return fmt.Errorf("queue size must be positive")
	}

	if c.Ingest.MaxBatchSize <= 0 {
		return fmt.Errorf("max_batch_size must be positive")
	}

	return nil
}
