// Package kafka provides real Kafka producer and consumer implementations
// for the SIEM event streaming pipeline.
package kafka

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

// Config holds Kafka connection and behavior configuration.
type Config struct {
	// Brokers is the list of Kafka broker addresses.
	Brokers []string `json:"brokers" yaml:"brokers"`

	// Topic is the default topic for producing/consuming.
	Topic string `json:"topic" yaml:"topic"`

	// ConsumerGroup is the consumer group ID.
	ConsumerGroup string `json:"consumer_group" yaml:"consumer_group"`

	// Partitions is the number of partitions when creating topics.
	Partitions int `json:"partitions" yaml:"partitions"`

	// ReplicationFactor for topic creation.
	ReplicationFactor int `json:"replication_factor" yaml:"replication_factor"`

	// RetentionMs is the retention period in milliseconds.
	RetentionMs int64 `json:"retention_ms" yaml:"retention_ms"`

	// MaxMessageBytes is the maximum message size.
	MaxMessageBytes int `json:"max_message_bytes" yaml:"max_message_bytes"`

	// CompressionType: none, gzip, snappy, lz4, zstd.
	CompressionType string `json:"compression_type" yaml:"compression_type"`

	// SecurityProtocol: PLAINTEXT, SSL, SASL_PLAINTEXT, SASL_SSL.
	SecurityProtocol string `json:"security_protocol" yaml:"security_protocol"`

	// SASLMechanism: PLAIN, SCRAM-SHA-256, SCRAM-SHA-512.
	SASLMechanism string `json:"sasl_mechanism,omitempty" yaml:"sasl_mechanism,omitempty"`

	// SASLUsername for SASL authentication.
	SASLUsername string `json:"sasl_username,omitempty" yaml:"sasl_username,omitempty"`

	// SASLPassword for SASL authentication.
	SASLPassword string `json:"sasl_password,omitempty" yaml:"sasl_password,omitempty"`

	// TLS configuration
	TLSEnabled    bool   `json:"tls_enabled" yaml:"tls_enabled"`
	TLSCertFile   string `json:"tls_cert_file,omitempty" yaml:"tls_cert_file,omitempty"`
	TLSKeyFile    string `json:"tls_key_file,omitempty" yaml:"tls_key_file,omitempty"`
	TLSCAFile     string `json:"tls_ca_file,omitempty" yaml:"tls_ca_file,omitempty"`
	TLSSkipVerify bool   `json:"tls_skip_verify,omitempty" yaml:"tls_skip_verify,omitempty"`

	// Producer settings
	ProducerBatchSize    int           `json:"producer_batch_size" yaml:"producer_batch_size"`
	ProducerBatchTimeout time.Duration `json:"producer_batch_timeout" yaml:"producer_batch_timeout"`
	ProducerMaxRetries   int           `json:"producer_max_retries" yaml:"producer_max_retries"`
	ProducerRetryBackoff time.Duration `json:"producer_retry_backoff" yaml:"producer_retry_backoff"`
	RequiredAcks         int           `json:"required_acks" yaml:"required_acks"` // -1=all, 0=none, 1=leader

	// Consumer settings
	ConsumerMinBytes  int           `json:"consumer_min_bytes" yaml:"consumer_min_bytes"`
	ConsumerMaxBytes  int           `json:"consumer_max_bytes" yaml:"consumer_max_bytes"`
	ConsumerMaxWait   time.Duration `json:"consumer_max_wait" yaml:"consumer_max_wait"`
	CommitInterval    time.Duration `json:"commit_interval" yaml:"commit_interval"`
	StartOffset       int64         `json:"start_offset" yaml:"start_offset"` // -1=latest, -2=earliest
	HeartbeatInterval time.Duration `json:"heartbeat_interval" yaml:"heartbeat_interval"`
	SessionTimeout    time.Duration `json:"session_timeout" yaml:"session_timeout"`
	RebalanceTimeout  time.Duration `json:"rebalance_timeout" yaml:"rebalance_timeout"`

	// Connection settings
	DialTimeout  time.Duration `json:"dial_timeout" yaml:"dial_timeout"`
	ReadTimeout  time.Duration `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout" yaml:"write_timeout"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Brokers:              []string{"localhost:9092"},
		Topic:                "siem-events",
		ConsumerGroup:        "siem-consumers",
		Partitions:           12,
		ReplicationFactor:    3,
		RetentionMs:          7 * 24 * 60 * 60 * 1000, // 7 days
		MaxMessageBytes:      1048576,                 // 1MB
		CompressionType:      "lz4",
		SecurityProtocol:     "PLAINTEXT",
		ProducerBatchSize:    100,
		ProducerBatchTimeout: 10 * time.Millisecond,
		ProducerMaxRetries:   3,
		ProducerRetryBackoff: 100 * time.Millisecond,
		RequiredAcks:         -1, // Wait for all replicas
		ConsumerMinBytes:     1,
		ConsumerMaxBytes:     10 * 1024 * 1024, // 10MB
		ConsumerMaxWait:      500 * time.Millisecond,
		CommitInterval:       time.Second,
		StartOffset:          kafka.LastOffset,
		HeartbeatInterval:    3 * time.Second,
		SessionTimeout:       30 * time.Second,
		RebalanceTimeout:     60 * time.Second,
		DialTimeout:          10 * time.Second,
		ReadTimeout:          30 * time.Second,
		WriteTimeout:         30 * time.Second,
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if len(c.Brokers) == 0 {
		return errors.New("kafka: at least one broker is required")
	}
	if c.Topic == "" {
		return errors.New("kafka: topic is required")
	}
	if c.Partitions < 1 {
		return errors.New("kafka: partitions must be at least 1")
	}
	if c.ReplicationFactor < 1 {
		return errors.New("kafka: replication factor must be at least 1")
	}

	// Validate security protocol
	validProtocols := map[string]bool{
		"PLAINTEXT": true, "SSL": true, "SASL_PLAINTEXT": true, "SASL_SSL": true,
	}
	if !validProtocols[c.SecurityProtocol] {
		return fmt.Errorf("kafka: invalid security protocol: %s", c.SecurityProtocol)
	}

	// Validate SASL mechanism if using SASL
	if c.SecurityProtocol == "SASL_PLAINTEXT" || c.SecurityProtocol == "SASL_SSL" {
		validMechanisms := map[string]bool{
			"PLAIN": true, "SCRAM-SHA-256": true, "SCRAM-SHA-512": true,
		}
		if !validMechanisms[c.SASLMechanism] {
			return fmt.Errorf("kafka: invalid SASL mechanism: %s", c.SASLMechanism)
		}
		if c.SASLUsername == "" || c.SASLPassword == "" {
			return errors.New("kafka: SASL username and password required for SASL authentication")
		}
	}

	return nil
}

// GetCompression returns the kafka-go compression codec.
func (c *Config) GetCompression() kafka.Compression {
	switch c.CompressionType {
	case "gzip":
		return kafka.Gzip
	case "snappy":
		return kafka.Snappy
	case "lz4":
		return kafka.Lz4
	case "zstd":
		return kafka.Zstd
	default:
		return 0 // No compression
	}
}

// GetDialer returns a configured kafka.Dialer with TLS and SASL if configured.
func (c *Config) GetDialer() (*kafka.Dialer, error) {
	dialer := &kafka.Dialer{
		Timeout:   c.DialTimeout,
		DualStack: true,
	}

	// Configure TLS
	if c.TLSEnabled || c.SecurityProtocol == "SSL" || c.SecurityProtocol == "SASL_SSL" {
		tlsConfig, err := c.getTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("kafka: failed to configure TLS: %w", err)
		}
		dialer.TLS = tlsConfig
	}

	// Configure SASL
	if c.SecurityProtocol == "SASL_PLAINTEXT" || c.SecurityProtocol == "SASL_SSL" {
		mechanism, err := c.getSASLMechanism()
		if err != nil {
			return nil, fmt.Errorf("kafka: failed to configure SASL: %w", err)
		}
		dialer.SASLMechanism = mechanism
	}

	return dialer, nil
}

// getTLSConfig builds a TLS configuration.
func (c *Config) getTLSConfig() (*tls.Config, error) {
	if c.TLSSkipVerify {
		slog.Warn("SECURITY WARNING: TLS certificate verification is disabled for Kafka - this is NOT recommended for production")
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.TLSSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	// Load CA certificate if specified
	if c.TLSCAFile != "" {
		caCert, err := os.ReadFile(c.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate if specified
	if c.TLSCertFile != "" && c.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// getSASLMechanism returns the configured SASL mechanism.
func (c *Config) getSASLMechanism() (sasl.Mechanism, error) {
	switch c.SASLMechanism {
	case "PLAIN":
		return plain.Mechanism{
			Username: c.SASLUsername,
			Password: c.SASLPassword,
		}, nil
	case "SCRAM-SHA-256":
		mechanism, err := scram.Mechanism(scram.SHA256, c.SASLUsername, c.SASLPassword)
		if err != nil {
			return nil, err
		}
		return mechanism, nil
	case "SCRAM-SHA-512":
		mechanism, err := scram.Mechanism(scram.SHA512, c.SASLUsername, c.SASLPassword)
		if err != nil {
			return nil, err
		}
		return mechanism, nil
	default:
		return nil, fmt.Errorf("unsupported SASL mechanism: %s", c.SASLMechanism)
	}
}

// Metrics holds Kafka producer/consumer metrics.
type Metrics struct {
	MessagesProduced int64
	BytesProduced    int64
	MessagesConsumed int64
	BytesConsumed    int64
	Errors           int64
	Retries          int64
	LastError        error
	LastErrorTime    time.Time
}

// HealthStatus represents the health of a Kafka component.
type HealthStatus struct {
	Healthy     bool          `json:"healthy"`
	Connected   bool          `json:"connected"`
	LastCheck   time.Time     `json:"last_check"`
	Latency     time.Duration `json:"latency"`
	Error       string        `json:"error,omitempty"`
	BrokerCount int           `json:"broker_count"`
}
