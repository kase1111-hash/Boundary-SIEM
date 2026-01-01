package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segmentio/kafka-go"
)

// Producer is a Kafka producer that sends messages to a topic.
type Producer struct {
	writer  *kafka.Writer
	config  *Config
	logger  *slog.Logger
	metrics *producerMetrics
	closed  atomic.Bool
	mu      sync.RWMutex
}

type producerMetrics struct {
	messagesProduced atomic.Int64
	bytesProduced    atomic.Int64
	errors           atomic.Int64
	retries          atomic.Int64
	lastError        atomic.Value // stores error
	lastErrorTime    atomic.Value // stores time.Time
}

// NewProducer creates a new Kafka producer.
func NewProducer(config *Config, logger *slog.Logger) (*Producer, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	dialer, err := config.GetDialer()
	if err != nil {
		return nil, err
	}

	// Configure writer
	writer := &kafka.Writer{
		Addr:         kafka.TCP(config.Brokers...),
		Topic:        config.Topic,
		Balancer:     &kafka.LeastBytes{},
		BatchSize:    config.ProducerBatchSize,
		BatchTimeout: config.ProducerBatchTimeout,
		MaxAttempts:  config.ProducerMaxRetries,
		WriteTimeout: config.WriteTimeout,
		ReadTimeout:  config.ReadTimeout,
		RequiredAcks: kafka.RequiredAcks(config.RequiredAcks),
		Compression:  config.GetCompression(),
		Transport: &kafka.Transport{
			Dial: dialer.DialFunc,
			TLS:  dialer.TLS,
			SASL: dialer.SASLMechanism,
		},
		Logger: kafka.LoggerFunc(func(msg string, args ...interface{}) {
			logger.Debug(fmt.Sprintf(msg, args...), "component", "kafka-writer")
		}),
		ErrorLogger: kafka.LoggerFunc(func(msg string, args ...interface{}) {
			logger.Error(fmt.Sprintf(msg, args...), "component", "kafka-writer")
		}),
	}

	p := &Producer{
		writer:  writer,
		config:  config,
		logger:  logger,
		metrics: &producerMetrics{},
	}

	logger.Info("kafka producer initialized",
		"brokers", config.Brokers,
		"topic", config.Topic,
		"compression", config.CompressionType,
		"batch_size", config.ProducerBatchSize,
	)

	return p, nil
}

// Produce sends a single message to Kafka.
func (p *Producer) Produce(ctx context.Context, key, value []byte) error {
	if p.closed.Load() {
		return ErrProducerClosed
	}

	msg := kafka.Message{
		Key:   key,
		Value: value,
		Time:  time.Now(),
	}

	return p.produceMessages(ctx, msg)
}

// ProduceWithTopic sends a message to a specific topic.
func (p *Producer) ProduceWithTopic(ctx context.Context, topic string, key, value []byte) error {
	if p.closed.Load() {
		return ErrProducerClosed
	}

	msg := kafka.Message{
		Topic: topic,
		Key:   key,
		Value: value,
		Time:  time.Now(),
	}

	return p.produceMessages(ctx, msg)
}

// ProduceJSON marshals the value to JSON and sends it.
func (p *Producer) ProduceJSON(ctx context.Context, key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("kafka: failed to marshal message: %w", err)
	}
	return p.Produce(ctx, []byte(key), data)
}

// ProduceBatch sends multiple messages in a single batch.
func (p *Producer) ProduceBatch(ctx context.Context, messages []kafka.Message) error {
	if p.closed.Load() {
		return ErrProducerClosed
	}

	return p.produceMessages(ctx, messages...)
}

// produceMessages is the core method that sends messages with retry logic.
func (p *Producer) produceMessages(ctx context.Context, messages ...kafka.Message) error {
	var lastErr error
	backoff := p.config.ProducerRetryBackoff

	for attempt := 0; attempt <= p.config.ProducerMaxRetries; attempt++ {
		if attempt > 0 {
			p.metrics.retries.Add(1)
			p.logger.Debug("retrying kafka produce",
				"attempt", attempt,
				"backoff", backoff,
			)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2 // Exponential backoff
			}
		}

		err := p.writer.WriteMessages(ctx, messages...)
		if err == nil {
			// Success - update metrics
			for _, msg := range messages {
				p.metrics.messagesProduced.Add(1)
				p.metrics.bytesProduced.Add(int64(len(msg.Value) + len(msg.Key)))
			}

			p.logger.Debug("produced messages",
				"count", len(messages),
				"topic", p.config.Topic,
			)
			return nil
		}

		lastErr = err
		p.metrics.errors.Add(1)
		p.metrics.lastError.Store(err)
		p.metrics.lastErrorTime.Store(time.Now())

		p.logger.Warn("kafka produce failed",
			"error", err,
			"attempt", attempt+1,
			"max_attempts", p.config.ProducerMaxRetries+1,
		)

		// Check for non-retryable errors
		if isNonRetryableError(err) {
			return fmt.Errorf("kafka: non-retryable error: %w", err)
		}
	}

	return fmt.Errorf("kafka: failed after %d attempts: %w", p.config.ProducerMaxRetries+1, lastErr)
}

// ProduceAsync sends a message asynchronously and reports errors via the error channel.
func (p *Producer) ProduceAsync(ctx context.Context, key, value []byte, errChan chan<- error) {
	go func() {
		if err := p.Produce(ctx, key, value); err != nil {
			select {
			case errChan <- err:
			default:
				p.logger.Error("async produce error channel full", "error", err)
			}
		}
	}()
}

// GetMetrics returns current producer metrics.
func (p *Producer) GetMetrics() Metrics {
	m := Metrics{
		MessagesProduced: p.metrics.messagesProduced.Load(),
		BytesProduced:    p.metrics.bytesProduced.Load(),
		Errors:           p.metrics.errors.Load(),
		Retries:          p.metrics.retries.Load(),
	}

	if err := p.metrics.lastError.Load(); err != nil {
		m.LastError = err.(error)
	}
	if t := p.metrics.lastErrorTime.Load(); t != nil {
		m.LastErrorTime = t.(time.Time)
	}

	return m
}

// Stats returns internal writer statistics.
func (p *Producer) Stats() kafka.WriterStats {
	return p.writer.Stats()
}

// HealthCheck verifies the producer can connect to Kafka.
func (p *Producer) HealthCheck(ctx context.Context) HealthStatus {
	status := HealthStatus{
		LastCheck: time.Now(),
	}

	if p.closed.Load() {
		status.Error = "producer is closed"
		return status
	}

	start := time.Now()

	// Try to get metadata from a broker
	dialer, err := p.config.GetDialer()
	if err != nil {
		status.Error = fmt.Sprintf("failed to create dialer: %v", err)
		return status
	}

	conn, err := dialer.DialContext(ctx, "tcp", p.config.Brokers[0])
	if err != nil {
		status.Error = fmt.Sprintf("failed to connect: %v", err)
		return status
	}
	defer conn.Close()

	brokers, err := conn.Brokers()
	if err != nil {
		status.Error = fmt.Sprintf("failed to get brokers: %v", err)
		return status
	}

	status.Latency = time.Since(start)
	status.Connected = true
	status.Healthy = true
	status.BrokerCount = len(brokers)

	return status
}

// Close closes the producer and flushes any buffered messages.
func (p *Producer) Close() error {
	if p.closed.Swap(true) {
		return nil // Already closed
	}

	p.logger.Info("closing kafka producer",
		"messages_produced", p.metrics.messagesProduced.Load(),
		"bytes_produced", p.metrics.bytesProduced.Load(),
	)

	if err := p.writer.Close(); err != nil {
		return fmt.Errorf("kafka: failed to close producer: %w", err)
	}

	return nil
}

// isNonRetryableError checks if an error should not be retried.
func isNonRetryableError(err error) bool {
	// These errors indicate issues that won't be resolved by retrying
	switch err {
	case kafka.MessageSizeTooLarge:
		return true
	case kafka.InvalidTopic:
		return true
	case kafka.TopicAuthorizationFailed:
		return true
	case kafka.GroupAuthorizationFailed:
		return true
	case kafka.ClusterAuthorizationFailed:
		return true
	}
	return false
}

// Common errors
var (
	ErrProducerClosed  = fmt.Errorf("kafka: producer is closed")
	ErrConsumerClosed  = fmt.Errorf("kafka: consumer is closed")
	ErrInvalidMessage  = fmt.Errorf("kafka: invalid message")
	ErrTopicNotFound   = fmt.Errorf("kafka: topic not found")
)
