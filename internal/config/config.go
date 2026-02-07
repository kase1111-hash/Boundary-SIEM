// Package config handles configuration loading for Boundary-SIEM.
package config

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"boundary-siem/internal/encryption"
	"boundary-siem/internal/secrets"

	"gopkg.in/yaml.v3"
)

// Config holds the complete application configuration.
type Config struct {
	Server          ServerConfig          `yaml:"server"`
	Ingest          IngestConfig          `yaml:"ingest"`
	Queue           QueueConfig           `yaml:"queue"`
	Validation      ValidationConfig      `yaml:"validation"`
	Auth            AuthConfig            `yaml:"auth"`
	CORS            CORSConfig            `yaml:"cors"`
	RateLimit       RateLimitConfig       `yaml:"rate_limit"`
	Logging         LoggingConfig         `yaml:"logging"`
	Storage         StorageConfig         `yaml:"storage"`
	Consumer        ConsumerConfig        `yaml:"consumer"`
	Secrets         SecretsConfig         `yaml:"secrets"`
	Encryption      EncryptionConfig      `yaml:"encryption"`
	SecurityHeaders SecurityHeadersConfig `yaml:"security_headers"`
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
	Retention   RetentionConfig   `yaml:"retention"`
}

// RetentionConfig holds data retention settings.
type RetentionConfig struct {
	EventsTTL     time.Duration `yaml:"events_ttl"`     // TTL for main events table
	CriticalTTL   time.Duration `yaml:"critical_ttl"`   // TTL for critical events
	QuarantineTTL time.Duration `yaml:"quarantine_ttl"`  // TTL for quarantined events
	AlertsTTL     time.Duration `yaml:"alerts_ttl"`     // TTL for alerts
	ArchiveEnabled bool         `yaml:"archive_enabled"` // Enable S3 archival before deletion
	ArchiveBucket  string       `yaml:"archive_bucket"`  // S3 bucket for archives
	ArchiveRegion  string       `yaml:"archive_region"`  // AWS region for S3
	ArchivePrefix  string       `yaml:"archive_prefix"`  // S3 key prefix
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
	EVM            EVMConfig `yaml:"evm"`
}

// EVMConfig holds EVM JSON-RPC poller settings.
type EVMConfig struct {
	Enabled      bool             `yaml:"enabled"`
	PollInterval time.Duration    `yaml:"poll_interval"`
	BatchSize    int              `yaml:"batch_size"`
	StartBlock   string           `yaml:"start_block"`
	Chains       []EVMChainConfig `yaml:"chains"`
}

// EVMChainConfig defines a single EVM chain to poll.
type EVMChainConfig struct {
	Name    string `yaml:"name"`
	ChainID int64  `yaml:"chain_id"`
	RPCURL  string `yaml:"rpc_url"`
	Enabled bool   `yaml:"enabled"`
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
	APIKeyHeader          string   `yaml:"api_key_header"`
	APIKeys               []string `yaml:"api_keys"`
	Enabled               bool     `yaml:"enabled"`
	DefaultAdminUsername  string   `yaml:"default_admin_username"`
	DefaultAdminPassword  string   `yaml:"default_admin_password"`
	DefaultAdminEmail     string   `yaml:"default_admin_email"`
	RequirePasswordChange bool     `yaml:"require_password_change"` // Force password change on first login
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// SecretsConfig holds secrets management settings.
type SecretsConfig struct {
	// Provider selection (vault, env, file)
	EnableVault bool `yaml:"enable_vault"`
	EnableEnv   bool `yaml:"enable_env"`
	EnableFile  bool `yaml:"enable_file"`

	// Vault configuration
	VaultAddress string        `yaml:"vault_address"`
	VaultToken   string        `yaml:"vault_token"`
	VaultPath    string        `yaml:"vault_path"`
	VaultTimeout time.Duration `yaml:"vault_timeout"`

	// File provider configuration
	FileSecretsDir string `yaml:"file_secrets_dir"`

	// Cache configuration
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// EncryptionConfig holds encryption at rest settings.
type EncryptionConfig struct {
	// Enabled indicates if encryption at rest is enabled.
	Enabled bool `yaml:"enabled"`

	// KeySource specifies where to get the encryption key.
	// Options: "env" (environment variable), "secret" (secrets manager), "file" (key file)
	KeySource string `yaml:"key_source"`

	// KeyName is the name/path of the encryption key.
	// For "env": environment variable name (default: BOUNDARY_ENCRYPTION_KEY)
	// For "secret": secret key name (default: ENCRYPTION_KEY)
	// For "file": path to key file (default: /etc/boundary-siem/encryption.key)
	KeyName string `yaml:"key_name"`

	// KeyVersion is the version of the encryption key (for key rotation).
	KeyVersion int `yaml:"key_version"`

	// EncryptSessionData enables encryption for session data.
	EncryptSessionData bool `yaml:"encrypt_session_data"`

	// EncryptUserData enables encryption for sensitive user data.
	EncryptUserData bool `yaml:"encrypt_user_data"`

	// EncryptAPIKeys enables encryption for API keys.
	EncryptAPIKeys bool `yaml:"encrypt_api_keys"`
}

// SecurityHeadersConfig holds security headers settings.
type SecurityHeadersConfig struct {
	// Enabled indicates if security headers are enabled.
	Enabled bool `yaml:"enabled"`

	// HSTS (HTTP Strict Transport Security)
	HSTSEnabled           bool `yaml:"hsts_enabled"`
	HSTSMaxAge            int  `yaml:"hsts_max_age"`
	HSTSIncludeSubdomains bool `yaml:"hsts_include_subdomains"`
	HSTSPreload           bool `yaml:"hsts_preload"`

	// CSP (Content Security Policy)
	CSPEnabled        bool     `yaml:"csp_enabled"`
	CSPDefaultSrc     []string `yaml:"csp_default_src"`
	CSPScriptSrc      []string `yaml:"csp_script_src"`
	CSPStyleSrc       []string `yaml:"csp_style_src"`
	CSPImgSrc         []string `yaml:"csp_img_src"`
	CSPFontSrc        []string `yaml:"csp_font_src"`
	CSPConnectSrc     []string `yaml:"csp_connect_src"`
	CSPFrameAncestors []string `yaml:"csp_frame_ancestors"`
	CSPReportOnly     bool     `yaml:"csp_report_only"`

	// Frame Options
	FrameOptionsEnabled bool   `yaml:"frame_options_enabled"`
	FrameOptionsValue   string `yaml:"frame_options_value"`

	// Content Type Options
	ContentTypeOptionsEnabled bool `yaml:"content_type_options_enabled"`

	// XSS Protection
	XSSProtectionEnabled bool   `yaml:"xss_protection_enabled"`
	XSSProtectionValue   string `yaml:"xss_protection_value"`

	// Referrer Policy
	ReferrerPolicyEnabled bool   `yaml:"referrer_policy_enabled"`
	ReferrerPolicyValue   string `yaml:"referrer_policy_value"`

	// Permissions Policy
	PermissionsPolicyEnabled bool   `yaml:"permissions_policy_enabled"`
	PermissionsPolicyValue   string `yaml:"permissions_policy_value"`

	// Cross-Origin Policies
	CrossOriginOpenerPolicyEnabled   bool   `yaml:"cross_origin_opener_policy_enabled"`
	CrossOriginOpenerPolicyValue     string `yaml:"cross_origin_opener_policy_value"`
	CrossOriginEmbedderPolicyEnabled bool   `yaml:"cross_origin_embedder_policy_enabled"`
	CrossOriginEmbedderPolicyValue   string `yaml:"cross_origin_embedder_policy_value"`
	CrossOriginResourcePolicyEnabled bool   `yaml:"cross_origin_resource_policy_enabled"`
	CrossOriginResourcePolicyValue   string `yaml:"cross_origin_resource_policy_value"`

	// Custom headers
	CustomHeaders map[string]string `yaml:"custom_headers"`
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
			EVM: EVMConfig{
				Enabled:      false,
				PollInterval: 12 * time.Second,
				BatchSize:    10,
				StartBlock:   "latest",
				Chains: []EVMChainConfig{
					{Name: "ethereum", ChainID: 1, RPCURL: "http://localhost:8545", Enabled: false},
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
			Enabled:       true,                            // Rate limiting enabled by default
			RequestsPerIP: 1000,                            // 1000 requests per IP per window
			WindowSize:    time.Minute,                     // 1 minute window
			BurstSize:     50,                              // Allow 50 extra requests burst
			CleanupPeriod: 5 * time.Minute,                 // Clean old entries every 5 minutes
			ExemptPaths:   []string{"/health", "/metrics"}, // Health/metrics exempt
			TrustProxy:    false,                           // Don't trust X-Forwarded-For by default
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
			Retention: RetentionConfig{
				EventsTTL:      90 * 24 * time.Hour,  // 90 days
				CriticalTTL:    365 * 24 * time.Hour, // 1 year
				QuarantineTTL:  30 * 24 * time.Hour,  // 30 days
				AlertsTTL:      365 * 24 * time.Hour, // 1 year
				ArchiveEnabled: false,
				ArchiveBucket:  "boundary-siem-archive",
				ArchiveRegion:  "us-east-1",
				ArchivePrefix:  "data/",
			},
		},
		Consumer: ConsumerConfig{
			Workers:      4,
			PollInterval: 10 * time.Millisecond,
			ShutdownWait: 30 * time.Second,
		},
		Secrets: SecretsConfig{
			EnableVault:    false,                  // Vault disabled by default
			EnableEnv:      true,                   // Environment variables enabled by default
			EnableFile:     false,                  // File secrets disabled by default
			VaultAddress:   "",                     // Must be configured if Vault is enabled
			VaultToken:     "",                     // Must be configured if Vault is enabled
			VaultPath:      "secret/boundary-siem", // Default Vault path
			VaultTimeout:   10 * time.Second,       // Vault request timeout
			FileSecretsDir: "/etc/secrets",         // Default directory for file-based secrets
			CacheTTL:       5 * time.Minute,        // Cache secrets for 5 minutes
		},
		Encryption: EncryptionConfig{
			Enabled:            false,                     // Encryption disabled by default
			KeySource:          "env",                     // Get key from environment by default
			KeyName:            "BOUNDARY_ENCRYPTION_KEY", // Default env var name
			KeyVersion:         1,                         // Initial key version
			EncryptSessionData: true,                      // Encrypt sessions when enabled
			EncryptUserData:    true,                      // Encrypt user data when enabled
			EncryptAPIKeys:     true,                      // Encrypt API keys when enabled
		},
		SecurityHeaders: SecurityHeadersConfig{
			Enabled:                          true,                                                           // Security headers enabled by default
			HSTSEnabled:                      true,                                                           // HSTS enabled
			HSTSMaxAge:                       31536000,                                                       // 1 year
			HSTSIncludeSubdomains:            true,                                                           // Include subdomains
			HSTSPreload:                      false,                                                          // Preload requires manual submission
			CSPEnabled:                       true,                                                           // CSP enabled
			CSPDefaultSrc:                    []string{"'self'"},                                             // Default to same origin
			CSPScriptSrc:                     []string{"'self'"},                                             // Scripts from same origin only
			CSPStyleSrc:                      []string{"'self'", "'unsafe-inline'"},                          // Styles with inline support
			CSPImgSrc:                        []string{"'self'", "data:", "https:"},                          // Images from self, data URIs, HTTPS
			CSPFontSrc:                       []string{"'self'"},                                             // Fonts from same origin
			CSPConnectSrc:                    []string{"'self'"},                                             // Connect to same origin
			CSPFrameAncestors:                []string{"'none'"},                                             // Prevent framing
			CSPReportOnly:                    false,                                                          // Enforce CSP
			FrameOptionsEnabled:              true,                                                           // X-Frame-Options enabled
			FrameOptionsValue:                "DENY",                                                         // Deny all framing
			ContentTypeOptionsEnabled:        true,                                                           // X-Content-Type-Options enabled
			XSSProtectionEnabled:             true,                                                           // X-XSS-Protection enabled
			XSSProtectionValue:               "1; mode=block",                                                // Block XSS
			ReferrerPolicyEnabled:            true,                                                           // Referrer-Policy enabled
			ReferrerPolicyValue:              "strict-origin-when-cross-origin",                              // Strict referrer
			PermissionsPolicyEnabled:         true,                                                           // Permissions-Policy enabled
			PermissionsPolicyValue:           "geolocation=(), microphone=(), camera=(), payment=(), usb=()", // Restrict features
			CrossOriginOpenerPolicyEnabled:   true,                                                           // COOP enabled
			CrossOriginOpenerPolicyValue:     "same-origin",                                                  // Same origin only
			CrossOriginEmbedderPolicyEnabled: false,                                                          // COEP disabled (can break integrations)
			CrossOriginEmbedderPolicyValue:   "require-corp",                                                 // Require CORP
			CrossOriginResourcePolicyEnabled: true,                                                           // CORP enabled
			CrossOriginResourcePolicyValue:   "same-origin",                                                  // Same origin only
			CustomHeaders:                    make(map[string]string),                                        // No custom headers by default
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

	// Secrets management settings
	if enabled := os.Getenv("SIEM_SECRETS_VAULT_ENABLED"); enabled == "true" {
		c.Secrets.EnableVault = true
	}

	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		c.Secrets.VaultAddress = addr
	}

	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		c.Secrets.VaultToken = token
	}

	if path := os.Getenv("VAULT_PATH"); path != "" {
		c.Secrets.VaultPath = path
	}

	if enabled := os.Getenv("SIEM_SECRETS_FILE_ENABLED"); enabled == "true" {
		c.Secrets.EnableFile = true
	}

	if dir := os.Getenv("SIEM_SECRETS_DIR"); dir != "" {
		c.Secrets.FileSecretsDir = dir
	}

	// Encryption settings
	if enabled := os.Getenv("SIEM_ENCRYPTION_ENABLED"); enabled == "true" {
		c.Encryption.Enabled = true
	}

	if keySource := os.Getenv("SIEM_ENCRYPTION_KEY_SOURCE"); keySource != "" {
		c.Encryption.KeySource = keySource
	}

	if keyName := os.Getenv("SIEM_ENCRYPTION_KEY_NAME"); keyName != "" {
		c.Encryption.KeyName = keyName
	}

	if version := os.Getenv("SIEM_ENCRYPTION_KEY_VERSION"); version != "" {
		fmt.Sscanf(version, "%d", &c.Encryption.KeyVersion)
	}

	// Security headers settings
	if enabled := os.Getenv("SIEM_SECURITY_HEADERS_ENABLED"); enabled == "false" {
		c.SecurityHeaders.Enabled = false
	}

	if enabled := os.Getenv("SIEM_HSTS_ENABLED"); enabled == "false" {
		c.SecurityHeaders.HSTSEnabled = false
	}

	if maxAge := os.Getenv("SIEM_HSTS_MAX_AGE"); maxAge != "" {
		fmt.Sscanf(maxAge, "%d", &c.SecurityHeaders.HSTSMaxAge)
	}

	if enabled := os.Getenv("SIEM_CSP_ENABLED"); enabled == "false" {
		c.SecurityHeaders.CSPEnabled = false
	}

	if frameOptions := os.Getenv("SIEM_FRAME_OPTIONS"); frameOptions != "" {
		c.SecurityHeaders.FrameOptionsValue = frameOptions
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

// LoadAuthFromEnv loads authentication configuration from environment variables.
// Environment variables take precedence over config file values.
func (c *Config) LoadAuthFromEnv() {
	if username := os.Getenv("BOUNDARY_ADMIN_USERNAME"); username != "" {
		c.Auth.DefaultAdminUsername = username
	}
	if password := os.Getenv("BOUNDARY_ADMIN_PASSWORD"); password != "" {
		c.Auth.DefaultAdminPassword = password
	}
	if email := os.Getenv("BOUNDARY_ADMIN_EMAIL"); email != "" {
		c.Auth.DefaultAdminEmail = email
	}
	if os.Getenv("BOUNDARY_REQUIRE_PASSWORD_CHANGE") == "true" {
		c.Auth.RequirePasswordChange = true
	}
}

// LoadAuthFromSecrets loads authentication configuration from the secrets manager.
// This method should be called after LoadAuthFromEnv() to allow secrets manager
// to override environment variables when configured.
func (c *Config) LoadAuthFromSecrets(ctx context.Context, mgr *secrets.Manager) error {
	// Try to get admin username from secrets
	if username, err := mgr.Get(ctx, "ADMIN_USERNAME"); err == nil {
		c.Auth.DefaultAdminUsername = username
	}

	// Try to get admin password from secrets
	if password, err := mgr.Get(ctx, "ADMIN_PASSWORD"); err == nil {
		c.Auth.DefaultAdminPassword = password
	}

	// Try to get admin email from secrets
	if email, err := mgr.Get(ctx, "ADMIN_EMAIL"); err == nil {
		c.Auth.DefaultAdminEmail = email
	}

	return nil
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

	// Validate admin password strength if provided
	if c.Auth.DefaultAdminPassword != "" {
		if err := ValidatePasswordStrength(c.Auth.DefaultAdminPassword); err != nil {
			return fmt.Errorf("invalid admin password: %w", err)
		}
	}

	return nil
}

// ValidatePasswordStrength validates password meets security requirements.
func ValidatePasswordStrength(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case char >= '!' && char <= '/' || char >= ':' && char <= '@' || char >= '[' && char <= '`' || char >= '{' && char <= '~':
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// NewSecretsManager creates a secrets manager from the configuration.
func (c *Config) NewSecretsManager() (*secrets.Manager, error) {
	secretsCfg := &secrets.Config{
		EnableVault:  c.Secrets.EnableVault,
		EnableEnv:    c.Secrets.EnableEnv,
		EnableFile:   c.Secrets.EnableFile,
		VaultAddress: c.Secrets.VaultAddress,
		VaultToken:   c.Secrets.VaultToken,
		VaultPath:    c.Secrets.VaultPath,
		CacheTTL:     c.Secrets.CacheTTL,
	}

	return secrets.NewManager(secretsCfg)
}

// GetSecret retrieves a secret using the secrets manager.
// This is a convenience method that creates a temporary secrets manager.
// For better performance, create a long-lived secrets manager instead.
func (c *Config) GetSecret(ctx context.Context, key string) (string, error) {
	mgr, err := c.NewSecretsManager()
	if err != nil {
		return "", fmt.Errorf("failed to create secrets manager: %w", err)
	}
	defer mgr.Close()

	return mgr.Get(ctx, key)
}

// GetSecretWithDefault retrieves a secret or returns a default value.
func (c *Config) GetSecretWithDefault(ctx context.Context, key, defaultValue string) string {
	value, err := c.GetSecret(ctx, key)
	if err != nil {
		return defaultValue
	}
	return value
}

// NewEncryptionEngine creates an encryption engine from the configuration.
func (c *Config) NewEncryptionEngine(ctx context.Context) (*encryption.Engine, error) {
	if !c.Encryption.Enabled {
		// Return disabled engine
		return encryption.NewEngine(&encryption.Config{
			Enabled: false,
		})
	}

	// Get encryption key based on key source
	var keyBytes []byte
	var err error

	switch c.Encryption.KeySource {
	case "env":
		// Get key from environment variable
		keyName := c.Encryption.KeyName
		if keyName == "" {
			keyName = "BOUNDARY_ENCRYPTION_KEY"
		}
		keyStr := os.Getenv(keyName)
		if keyStr == "" {
			return nil, fmt.Errorf("encryption key not found in environment variable %s", keyName)
		}
		// Decode from base64
		keyBytes, err = base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			// Try using as raw string
			keyBytes = []byte(keyStr)
		}

	case "secret":
		// Get key from secrets manager
		mgr, err := c.NewSecretsManager()
		if err != nil {
			return nil, fmt.Errorf("failed to create secrets manager: %w", err)
		}
		defer mgr.Close()

		keyName := c.Encryption.KeyName
		if keyName == "" {
			keyName = "ENCRYPTION_KEY"
		}

		keyStr, err := mgr.Get(ctx, keyName)
		if err != nil {
			return nil, fmt.Errorf("failed to get encryption key from secrets manager: %w", err)
		}

		// Decode from base64
		keyBytes, err = base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			// Try using as raw string
			keyBytes = []byte(keyStr)
		}

	case "file":
		// Get key from file
		keyPath := c.Encryption.KeyName
		if keyPath == "" {
			keyPath = "/etc/boundary-siem/encryption.key"
		}

		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read encryption key file %s: %w", keyPath, err)
		}

		// Try to decode from base64
		keyBytes, err = base64.StdEncoding.DecodeString(string(keyData))
		if err != nil {
			// Use raw bytes
			keyBytes = keyData
		}

	default:
		return nil, fmt.Errorf("invalid key source: %s (must be 'env', 'secret', or 'file')", c.Encryption.KeySource)
	}

	// Create encryption engine
	return encryption.NewEngine(&encryption.Config{
		Enabled:    true,
		MasterKey:  keyBytes,
		KeyVersion: c.Encryption.KeyVersion,
	})
}

// GenerateEncryptionKey generates a new encryption key and returns it as base64.
// This is a helper for initial setup and key rotation.
func GenerateEncryptionKey() (string, error) {
	return encryption.GenerateKeyBase64()
}
