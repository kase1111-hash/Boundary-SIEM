// Package config - Integration configuration types
package config

import (
	"time"
)

// IntegrationsConfig holds configuration for all external integrations.
type IntegrationsConfig struct {
	BoundaryDaemon BoundaryDaemonConfig `yaml:"boundarydaemon"`
}

// BoundaryDaemonConfig holds configuration for the Boundary Daemon integration.
type BoundaryDaemonConfig struct {
	Enabled    bool                       `yaml:"enabled"`
	Client     BoundaryDaemonClientConfig `yaml:"client"`
	Ingester   BoundaryDaemonIngesterConfig `yaml:"ingester"`
	Normalizer BoundaryDaemonNormalizerConfig `yaml:"normalizer"`
}

// BoundaryDaemonClientConfig holds client configuration for Boundary Daemon.
type BoundaryDaemonClientConfig struct {
	BaseURL      string        `yaml:"base_url"`
	APIKey       string        `yaml:"api_key"`
	Timeout      time.Duration `yaml:"timeout"`
	MaxRetries   int           `yaml:"max_retries"`
	RetryBackoff time.Duration `yaml:"retry_backoff"`
}

// BoundaryDaemonIngesterConfig holds ingester configuration for Boundary Daemon.
type BoundaryDaemonIngesterConfig struct {
	PollInterval      time.Duration `yaml:"poll_interval"`
	SessionBatchSize  int           `yaml:"session_batch_size"`
	AuthBatchSize     int           `yaml:"auth_batch_size"`
	AccessBatchSize   int           `yaml:"access_batch_size"`
	ThreatBatchSize   int           `yaml:"threat_batch_size"`
	PolicyBatchSize   int           `yaml:"policy_batch_size"`
	AuditBatchSize    int           `yaml:"audit_batch_size"`
	IngestSessions    bool          `yaml:"ingest_sessions"`
	IngestAuth        bool          `yaml:"ingest_auth"`
	IngestAccess      bool          `yaml:"ingest_access"`
	IngestThreats     bool          `yaml:"ingest_threats"`
	IngestPolicies    bool          `yaml:"ingest_policies"`
	IngestAuditLogs   bool          `yaml:"ingest_audit_logs"`
	VerifyAuditLogs   bool          `yaml:"verify_audit_logs"`
	MinThreatSeverity string        `yaml:"min_threat_severity"`
}

// BoundaryDaemonNormalizerConfig holds normalizer configuration for Boundary Daemon.
type BoundaryDaemonNormalizerConfig struct {
	DefaultTenantID string `yaml:"default_tenant_id"`
	SourceHost      string `yaml:"source_host"`
	SourceVersion   string `yaml:"source_version"`
}

// DefaultBoundaryDaemonConfig returns the default Boundary Daemon configuration.
func DefaultBoundaryDaemonConfig() BoundaryDaemonConfig {
	return BoundaryDaemonConfig{
		Enabled: false,
		Client: BoundaryDaemonClientConfig{
			BaseURL:      "http://localhost:9000",
			Timeout:      30 * time.Second,
			MaxRetries:   3,
			RetryBackoff: time.Second,
		},
		Ingester: BoundaryDaemonIngesterConfig{
			PollInterval:      30 * time.Second,
			SessionBatchSize:  500,
			AuthBatchSize:     500,
			AccessBatchSize:   500,
			ThreatBatchSize:   100,
			PolicyBatchSize:   200,
			AuditBatchSize:    500,
			IngestSessions:    true,
			IngestAuth:        true,
			IngestAccess:      true,
			IngestThreats:     true,
			IngestPolicies:    true,
			IngestAuditLogs:   true,
			VerifyAuditLogs:   false,
			MinThreatSeverity: "low",
		},
		Normalizer: BoundaryDaemonNormalizerConfig{
			DefaultTenantID: "default",
			SourceHost:      "localhost",
			SourceVersion:   "1.0.0",
		},
	}
}
