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
	CORS       CORSConfig       `yaml:"cors"`
	RateLimit  RateLimitConfig  `yaml:"rate_limit"`
	Logging    LoggingConfig    `yaml:"logging"`
	Storage    StorageConfig    `yaml:"storage"`
	Consumer   ConsumerConfig   `yaml:"consumer"`
}

// RateLimitConfig holds rate limiting settings.
type RateLimitConfig struct {
	Enabled       bool          `yaml:"enabled"`
	RequestsPerIP int           `yaml:"requests_per_ip"` // Max requests per IP per window
	WindowSize    time.Duration `yaml:"window_size"`     // Time window for rate limiting
	BurstSize     int           `yaml:"burst_size"`      // Allow burst above limit temporarily
	CleanupPeriod time.Duration `yaml:"cleanup_period"`  // How often to clean old entries
	ExemptPaths   []string      `yaml:"exempt_paths"`    // Paths exempt from rate limiting
	TrustProxy    bool          `yaml:"trust_proxy"`     // Trust X-Forwarded-For header
}

// CORSConfig holds CORS settings.
type CORSConfig struct {
	Enabled          bool     `yaml:"enabled"`
	AllowedOrigins   []string `yaml:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers"`
	ExposedHeaders   []string `yaml:"exposed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials"`
	MaxAge           int      `yaml:"max_age"` // Preflight cache duration in seconds
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
	MaxBatchSize   int       `yaml:"max_batch_size"`
	MaxPayloadSize int       `yaml:"max_payload_size"`
	CEF            CEFConfig `yaml:"cef"`
}

// CEFConfig holds CEF ingestion settings.
type CEFConfig struct {
	UDP        CEFUDPConfig        `yaml:"udp"`
	DTLS       CEFDTLSConfig       `yaml:"dtls"`
	TCP        CEFTCPConfig        `yaml:"tcp"`
	Parser     CEFParserConfig     `yaml:"parser"`
	Normalizer CEFNormalizerConfig `yaml:"normalizer"`
}

// CEFUDPConfig holds UDP server settings for CEF.
// DEPRECATED: Use CEFDTLSConfig for secure UDP ingestion.
type CEFUDPConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Address        string `yaml:"address"`
	BufferSize     int    `yaml:"buffer_size"`
	Workers        int    `yaml:"workers"`
	MaxMessageSize int    `yaml:"max_message_size"`
}

// CEFDTLSConfig holds DTLS (secure UDP) server settings for CEF.
type CEFDTLSConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Address           string        `yaml:"address"`
	CertFile          string        `yaml:"cert_file"`
	KeyFile           string        `yaml:"key_file"`
	CAFile            string        `yaml:"ca_file"`
	RequireClientCert bool          `yaml:"require_client_cert"`
	Workers           int           `yaml:"workers"`
	MaxMessageSize    int           `yaml:"max_message_size"`
	ConnectionTimeout time.Duration `yaml:"connection_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	AllowInsecure     bool          `yaml:"allow_insecure"` // Allow fallback to plain UDP (NOT RECOMMENDED)
}

// CEFTCPConfig holds TCP server settings for CEF.
type CEFTCPConfig struct {
	Enabled        bool          `yaml:"enabled"`
	Address        string        `yaml:"address"`
	TLSEnabled     bool          `yaml:"tls_enabled"`
	TLSCertFile    string        `yaml:"tls_cert_file"`
	TLSKeyFile     string        `yaml:"tls_key_file"`
	MaxConnections int           `yaml:"max_connections"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
	MaxLineLength  int           `yaml:"max_line_length"`
}

// CEFParserConfig holds CEF parser settings.
type CEFParserConfig struct {
	StrictMode    bool `yaml:"strict_mode"`
	MaxExtensions int  `yaml:"max_extensions"`
}

// CEFNormalizerConfig holds CEF normalizer settings.
type CEFNormalizerConfig struct {
	DefaultTenantID string `yaml:"default_tenant_id"`
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
			CEF: CEFConfig{
				UDP: CEFUDPConfig{
					Enabled:        false, // DEPRECATED: Disabled by default, use DTLS instead
					Address:        ":5514",
					BufferSize:     16 * 1024 * 1024, // 16MB
					Workers:        8,
					MaxMessageSize: 65535,
				},
				DTLS: CEFDTLSConfig{
					Enabled:           false, // Enable when certificates are configured
					Address:           ":5516",
					Workers:           8,
					MaxMessageSize:    65535,
					ConnectionTimeout: 30 * time.Second,
					IdleTimeout:       5 * time.Minute,
					AllowInsecure:     false,
					RequireClientCert: false,
				},
				TCP: CEFTCPConfig{
					Enabled:        true,
					Address:        ":5515",
					TLSEnabled:     false,
					MaxConnections: 1000,
					IdleTimeout:    5 * time.Minute,
					MaxLineLength:  65535,
				},
				Parser: CEFParserConfig{
					StrictMode:    false,
					MaxExtensions: 100,
				},
				Normalizer: CEFNormalizerConfig{
					DefaultTenantID: "default",
				},
			},
		},
		Queue: QueueConfig{
			Size:           100000,
			OverflowPolicy: "reject",
		},
		Validation: ValidationConfig{
			MaxEventAge: 7 * 24 * time.Hour,
			MaxFuture:   5 * time.Minute,
			StrictMode:  false, // Disabled by default - enable for production
		},
		Auth: AuthConfig{
			APIKeyHeader: "X-API-Key",
			Enabled:      false, // Disabled by default for development
		},
		CORS: CORSConfig{
			Enabled:        true, // CORS enabled by default for API access
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
			AllowedHeaders: []string{
				"Accept",
				"Authorization",
				"Content-Type",
				"X-API-Key",
				"X-Request-ID",
				"X-Tenant-ID",
			},
			ExposedHeaders: []string{
				"X-Request-ID",
				"X-RateLimit-Limit",
				"X-RateLimit-Remaining",
				"X-RateLimit-Reset",
			},
			AllowCredentials: false, // Set to false when AllowedOrigins is "*"
			MaxAge:           86400, // 24 hours preflight cache
		},
		RateLimit: RateLimitConfig{
			Enabled:       true,              // Rate limiting enabled by default
			RequestsPerIP: 1000,              // 1000 requests per IP per window
			WindowSize:    time.Minute,       // 1 minute window
			BurstSize:     50,                // Allow 50 extra requests burst
			CleanupPeriod: 5 * time.Minute,   // Clean old entries every 5 minutes
			ExemptPaths:   []string{"/health", "/metrics"}, // Health/metrics exempt
			TrustProxy:    false,             // Don't trust X-Forwarded-For by default
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

	// CORS settings
	if enabled := os.Getenv("SIEM_CORS_ENABLED"); enabled == "false" {
		c.CORS.Enabled = false
	}

	if origins := os.Getenv("SIEM_CORS_ORIGINS"); origins != "" {
		c.CORS.AllowedOrigins = splitAndTrim(origins, ",")
	}

	// Rate limit settings
	if enabled := os.Getenv("SIEM_RATELIMIT_ENABLED"); enabled == "false" {
		c.RateLimit.Enabled = false
	}

	if rps := os.Getenv("SIEM_RATELIMIT_RPS"); rps != "" {
		fmt.Sscanf(rps, "%d", &c.RateLimit.RequestsPerIP)
	}

	if burst := os.Getenv("SIEM_RATELIMIT_BURST"); burst != "" {
		fmt.Sscanf(burst, "%d", &c.RateLimit.BurstSize)
	}
}

// splitAndTrim splits a string by separator and trims whitespace from each part.
func splitAndTrim(s, sep string) []string {
	parts := make([]string, 0)
	for _, part := range splitString(s, sep) {
		trimmed := trimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

// splitString splits a string by separator (simple implementation to avoid strings package).
func splitString(s, sep string) []string {
	if s == "" {
		return nil
	}
	var result []string
	start := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

// trimSpace trims leading and trailing whitespace.
func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
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
