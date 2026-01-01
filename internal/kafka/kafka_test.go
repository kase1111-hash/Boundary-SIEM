package kafka

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if len(cfg.Brokers) == 0 {
		t.Error("expected default brokers")
	}
	if cfg.Topic == "" {
		t.Error("expected default topic")
	}
	if cfg.ConsumerGroup == "" {
		t.Error("expected default consumer group")
	}
	if cfg.Partitions < 1 {
		t.Error("expected partitions >= 1")
	}
	if cfg.ReplicationFactor < 1 {
		t.Error("expected replication factor >= 1")
	}
	if cfg.ProducerBatchSize < 1 {
		t.Error("expected batch size >= 1")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name:    "valid config",
			modify:  func(c *Config) {},
			wantErr: false,
		},
		{
			name: "empty brokers",
			modify: func(c *Config) {
				c.Brokers = nil
			},
			wantErr: true,
		},
		{
			name: "empty topic",
			modify: func(c *Config) {
				c.Topic = ""
			},
			wantErr: true,
		},
		{
			name: "invalid partitions",
			modify: func(c *Config) {
				c.Partitions = 0
			},
			wantErr: true,
		},
		{
			name: "invalid replication factor",
			modify: func(c *Config) {
				c.ReplicationFactor = 0
			},
			wantErr: true,
		},
		{
			name: "invalid security protocol",
			modify: func(c *Config) {
				c.SecurityProtocol = "INVALID"
			},
			wantErr: true,
		},
		{
			name: "SASL without credentials",
			modify: func(c *Config) {
				c.SecurityProtocol = "SASL_PLAINTEXT"
				c.SASLMechanism = "PLAIN"
				c.SASLUsername = ""
			},
			wantErr: true,
		},
		{
			name: "valid SASL config",
			modify: func(c *Config) {
				c.SecurityProtocol = "SASL_PLAINTEXT"
				c.SASLMechanism = "PLAIN"
				c.SASLUsername = "user"
				c.SASLPassword = "pass"
			},
			wantErr: false,
		},
		{
			name: "SCRAM-SHA-256",
			modify: func(c *Config) {
				c.SecurityProtocol = "SASL_SSL"
				c.SASLMechanism = "SCRAM-SHA-256"
				c.SASLUsername = "user"
				c.SASLPassword = "pass"
				c.TLSSkipVerify = true
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)

			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetCompression(t *testing.T) {
	tests := []struct {
		compression string
		wantNonZero bool
	}{
		{"gzip", true},
		{"snappy", true},
		{"lz4", true},
		{"zstd", true},
		{"none", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.compression, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.CompressionType = tt.compression

			result := cfg.GetCompression()
			if tt.wantNonZero && result == 0 {
				t.Errorf("expected non-zero compression for %s", tt.compression)
			}
			if !tt.wantNonZero && result != 0 {
				t.Errorf("expected zero compression for %s", tt.compression)
			}
		})
	}
}

func TestGetDialer(t *testing.T) {
	cfg := DefaultConfig()

	dialer, err := cfg.GetDialer()
	if err != nil {
		t.Fatalf("GetDialer() error = %v", err)
	}

	if dialer == nil {
		t.Error("expected non-nil dialer")
	}

	if dialer.Timeout != cfg.DialTimeout {
		t.Errorf("expected timeout %v, got %v", cfg.DialTimeout, dialer.Timeout)
	}
}

func TestGetDialerWithTLS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLSEnabled = true
	cfg.TLSSkipVerify = true

	dialer, err := cfg.GetDialer()
	if err != nil {
		t.Fatalf("GetDialer() error = %v", err)
	}

	if dialer.TLS == nil {
		t.Error("expected TLS config to be set")
	}
}

// Integration tests - skipped if Kafka is not available
func getTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func skipIfNoKafka(t *testing.T) {
	t.Helper()
	brokers := os.Getenv("KAFKA_BROKERS")
	if brokers == "" {
		t.Skip("KAFKA_BROKERS not set, skipping integration test")
	}
}

func TestProducerIntegration(t *testing.T) {
	skipIfNoKafka(t)

	cfg := DefaultConfig()
	cfg.Brokers = []string{os.Getenv("KAFKA_BROKERS")}
	cfg.Topic = "test-topic-" + time.Now().Format("20060102150405")

	producer, err := NewProducer(cfg, getTestLogger())
	if err != nil {
		t.Fatalf("NewProducer() error = %v", err)
	}
	defer producer.Close()

	ctx := context.Background()

	// Test health check
	status := producer.HealthCheck(ctx)
	if !status.Healthy {
		t.Errorf("expected producer to be healthy: %s", status.Error)
	}

	// Test produce
	err = producer.Produce(ctx, []byte("key"), []byte("value"))
	if err != nil {
		t.Errorf("Produce() error = %v", err)
	}

	// Check metrics
	metrics := producer.GetMetrics()
	if metrics.MessagesProduced != 1 {
		t.Errorf("expected 1 message produced, got %d", metrics.MessagesProduced)
	}
}

func TestConsumerIntegration(t *testing.T) {
	skipIfNoKafka(t)

	cfg := DefaultConfig()
	cfg.Brokers = []string{os.Getenv("KAFKA_BROKERS")}
	cfg.Topic = "test-topic-" + time.Now().Format("20060102150405")
	cfg.ConsumerGroup = "test-group-" + time.Now().Format("20060102150405")
	cfg.StartOffset = -2 // Earliest

	received := make(chan Message, 1)
	handler := func(ctx context.Context, msg Message) error {
		received <- msg
		return nil
	}

	consumer, err := NewConsumer(cfg, handler, getTestLogger())
	if err != nil {
		t.Fatalf("NewConsumer() error = %v", err)
	}
	defer consumer.Stop()

	ctx := context.Background()

	// Test health check
	status := consumer.HealthCheck(ctx)
	if !status.Connected {
		t.Errorf("expected consumer to be connected: %s", status.Error)
	}
}

func TestAdminIntegration(t *testing.T) {
	skipIfNoKafka(t)

	cfg := DefaultConfig()
	cfg.Brokers = []string{os.Getenv("KAFKA_BROKERS")}

	admin, err := NewAdmin(cfg, getTestLogger())
	if err != nil {
		t.Fatalf("NewAdmin() error = %v", err)
	}

	ctx := context.Background()

	// Test health check
	status := admin.HealthCheck(ctx)
	if !status.Healthy {
		t.Errorf("expected admin to be healthy: %s", status.Error)
	}

	// Test list brokers
	brokers, err := admin.ListBrokers(ctx)
	if err != nil {
		t.Errorf("ListBrokers() error = %v", err)
	}
	if len(brokers) == 0 {
		t.Error("expected at least one broker")
	}

	// Test list topics
	topics, err := admin.ListTopics(ctx)
	if err != nil {
		t.Errorf("ListTopics() error = %v", err)
	}
	t.Logf("Found %d topics", len(topics))
}

// Unit tests for producer
func TestProducerClosed(t *testing.T) {
	cfg := DefaultConfig()
	producer := &Producer{
		config:  cfg,
		logger:  getTestLogger(),
		metrics: &producerMetrics{},
	}
	producer.closed.Store(true)

	err := producer.Produce(context.Background(), []byte("key"), []byte("value"))
	if err != ErrProducerClosed {
		t.Errorf("expected ErrProducerClosed, got %v", err)
	}
}

// Unit tests for consumer
func TestConsumerStartTwice(t *testing.T) {
	cfg := DefaultConfig()
	consumer := &Consumer{
		config:  cfg,
		logger:  getTestLogger(),
		metrics: &consumerMetrics{},
	}
	consumer.started.Store(true)

	err := consumer.StartAsync()
	if err == nil {
		t.Error("expected error when starting twice")
	}
}

func TestConsumerGroupMetrics(t *testing.T) {
	// Create mock consumers with metrics
	c1 := &Consumer{metrics: &consumerMetrics{}}
	c1.metrics.messagesConsumed.Store(100)
	c1.metrics.bytesConsumed.Store(1000)

	c2 := &Consumer{metrics: &consumerMetrics{}}
	c2.metrics.messagesConsumed.Store(200)
	c2.metrics.bytesConsumed.Store(2000)

	cg := &ConsumerGroup{
		consumers: []*Consumer{c1, c2},
	}

	metrics := cg.GetMetrics()
	if metrics.MessagesConsumed != 300 {
		t.Errorf("expected 300 messages, got %d", metrics.MessagesConsumed)
	}
	if metrics.BytesConsumed != 3000 {
		t.Errorf("expected 3000 bytes, got %d", metrics.BytesConsumed)
	}
}
