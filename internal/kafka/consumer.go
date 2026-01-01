package kafka

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segmentio/kafka-go"
)

// MessageHandler is a function that processes consumed messages.
// Return nil to acknowledge the message, or an error to reprocess.
type MessageHandler func(ctx context.Context, msg Message) error

// Message represents a consumed Kafka message.
type Message struct {
	Topic     string
	Partition int
	Offset    int64
	Key       []byte
	Value     []byte
	Headers   []Header
	Time      time.Time
}

// Header represents a Kafka message header.
type Header struct {
	Key   string
	Value []byte
}

// Consumer is a Kafka consumer that reads messages from topics.
type Consumer struct {
	reader  *kafka.Reader
	config  *Config
	logger  *slog.Logger
	handler MessageHandler
	metrics *consumerMetrics
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	closed  atomic.Bool
	started atomic.Bool
}

type consumerMetrics struct {
	messagesConsumed atomic.Int64
	bytesConsumed    atomic.Int64
	errors           atomic.Int64
	rebalances       atomic.Int64
	lag              atomic.Int64
	lastOffset       atomic.Int64
	lastError        atomic.Value
	lastErrorTime    atomic.Value
}

// NewConsumer creates a new Kafka consumer.
func NewConsumer(config *Config, handler MessageHandler, logger *slog.Logger) (*Consumer, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	if handler == nil {
		return nil, errors.New("kafka: message handler is required")
	}

	dialer, err := config.GetDialer()
	if err != nil {
		return nil, err
	}

	// Configure reader
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:           config.Brokers,
		GroupID:           config.ConsumerGroup,
		Topic:             config.Topic,
		Dialer:            dialer,
		MinBytes:          config.ConsumerMinBytes,
		MaxBytes:          config.ConsumerMaxBytes,
		MaxWait:           config.ConsumerMaxWait,
		CommitInterval:    config.CommitInterval,
		StartOffset:       config.StartOffset,
		HeartbeatInterval: config.HeartbeatInterval,
		SessionTimeout:    config.SessionTimeout,
		RebalanceTimeout:  config.RebalanceTimeout,
		ReadBackoffMin:    100 * time.Millisecond,
		ReadBackoffMax:    time.Second,
		Logger: kafka.LoggerFunc(func(msg string, args ...interface{}) {
			logger.Debug(fmt.Sprintf(msg, args...), "component", "kafka-reader")
		}),
		ErrorLogger: kafka.LoggerFunc(func(msg string, args ...interface{}) {
			logger.Error(fmt.Sprintf(msg, args...), "component", "kafka-reader")
		}),
	})

	ctx, cancel := context.WithCancel(context.Background())

	c := &Consumer{
		reader:  reader,
		config:  config,
		logger:  logger,
		handler: handler,
		metrics: &consumerMetrics{},
		ctx:     ctx,
		cancel:  cancel,
	}

	logger.Info("kafka consumer initialized",
		"brokers", config.Brokers,
		"topic", config.Topic,
		"group", config.ConsumerGroup,
		"start_offset", config.StartOffset,
	)

	return c, nil
}

// Start begins consuming messages. This is a blocking call.
// Use StartAsync for non-blocking consumption.
func (c *Consumer) Start() error {
	if c.started.Swap(true) {
		return errors.New("kafka: consumer already started")
	}

	c.logger.Info("starting kafka consumer",
		"topic", c.config.Topic,
		"group", c.config.ConsumerGroup,
	)

	return c.consumeLoop()
}

// StartAsync begins consuming messages in a goroutine.
// Returns immediately. Use Stop() to stop consumption.
func (c *Consumer) StartAsync() error {
	if c.started.Swap(true) {
		return errors.New("kafka: consumer already started")
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		if err := c.consumeLoop(); err != nil && !errors.Is(err, context.Canceled) {
			c.logger.Error("consumer loop exited with error", "error", err)
		}
	}()

	c.logger.Info("kafka consumer started async",
		"topic", c.config.Topic,
		"group", c.config.ConsumerGroup,
	)

	return nil
}

// consumeLoop is the main consumption loop.
func (c *Consumer) consumeLoop() error {
	for {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
		}

		// Fetch message with context
		kafkaMsg, err := c.reader.FetchMessage(c.ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}

			c.metrics.errors.Add(1)
			c.metrics.lastError.Store(err)
			c.metrics.lastErrorTime.Store(time.Now())

			c.logger.Error("failed to fetch message",
				"error", err,
				"topic", c.config.Topic,
			)

			// Back off on errors
			select {
			case <-c.ctx.Done():
				return c.ctx.Err()
			case <-time.After(time.Second):
				continue
			}
		}

		// Convert to our message type
		msg := Message{
			Topic:     kafkaMsg.Topic,
			Partition: kafkaMsg.Partition,
			Offset:    kafkaMsg.Offset,
			Key:       kafkaMsg.Key,
			Value:     kafkaMsg.Value,
			Time:      kafkaMsg.Time,
			Headers:   make([]Header, len(kafkaMsg.Headers)),
		}
		for i, h := range kafkaMsg.Headers {
			msg.Headers[i] = Header{Key: h.Key, Value: h.Value}
		}

		// Process message
		if err := c.processMessage(msg); err != nil {
			c.logger.Error("failed to process message",
				"error", err,
				"topic", msg.Topic,
				"partition", msg.Partition,
				"offset", msg.Offset,
			)
			// Continue processing - don't commit this message
			continue
		}

		// Commit offset
		if err := c.reader.CommitMessages(c.ctx, kafkaMsg); err != nil {
			c.logger.Error("failed to commit offset",
				"error", err,
				"offset", kafkaMsg.Offset,
			)
		}

		// Update metrics
		c.metrics.messagesConsumed.Add(1)
		c.metrics.bytesConsumed.Add(int64(len(kafkaMsg.Value) + len(kafkaMsg.Key)))
		c.metrics.lastOffset.Store(kafkaMsg.Offset)
	}
}

// processMessage calls the handler and handles any errors.
func (c *Consumer) processMessage(msg Message) error {
	// Create a timeout context for processing
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()

	if err := c.handler(ctx, msg); err != nil {
		c.metrics.errors.Add(1)
		return err
	}

	return nil
}

// GetMetrics returns current consumer metrics.
func (c *Consumer) GetMetrics() Metrics {
	m := Metrics{
		MessagesConsumed: c.metrics.messagesConsumed.Load(),
		BytesConsumed:    c.metrics.bytesConsumed.Load(),
		Errors:           c.metrics.errors.Load(),
	}

	if err := c.metrics.lastError.Load(); err != nil {
		m.LastError = err.(error)
	}
	if t := c.metrics.lastErrorTime.Load(); t != nil {
		m.LastErrorTime = t.(time.Time)
	}

	return m
}

// Lag returns the consumer lag (approximate).
func (c *Consumer) Lag() int64 {
	return c.metrics.lag.Load()
}

// Stats returns internal reader statistics.
func (c *Consumer) Stats() kafka.ReaderStats {
	return c.reader.Stats()
}

// HealthCheck verifies the consumer can connect to Kafka.
func (c *Consumer) HealthCheck(ctx context.Context) HealthStatus {
	status := HealthStatus{
		LastCheck: time.Now(),
	}

	if c.closed.Load() {
		status.Error = "consumer is closed"
		return status
	}

	start := time.Now()

	// Try to get metadata from a broker
	dialer, err := c.config.GetDialer()
	if err != nil {
		status.Error = fmt.Sprintf("failed to create dialer: %v", err)
		return status
	}

	conn, err := dialer.DialContext(ctx, "tcp", c.config.Brokers[0])
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
	status.Healthy = c.started.Load() && !c.closed.Load()
	status.BrokerCount = len(brokers)

	return status
}

// Stop gracefully stops the consumer.
func (c *Consumer) Stop() error {
	if c.closed.Swap(true) {
		return nil // Already closed
	}

	c.logger.Info("stopping kafka consumer",
		"messages_consumed", c.metrics.messagesConsumed.Load(),
		"bytes_consumed", c.metrics.bytesConsumed.Load(),
	)

	// Cancel context to stop consume loop
	c.cancel()

	// Wait for goroutines to finish
	c.wg.Wait()

	// Close reader
	if err := c.reader.Close(); err != nil {
		return fmt.Errorf("kafka: failed to close consumer: %w", err)
	}

	return nil
}

// ConsumerGroup provides more advanced consumer group management.
type ConsumerGroup struct {
	consumers []*Consumer
	config    *Config
	logger    *slog.Logger
	handler   MessageHandler
	mu        sync.Mutex
	started   bool
}

// NewConsumerGroup creates a consumer group with multiple consumers.
func NewConsumerGroup(config *Config, numConsumers int, handler MessageHandler, logger *slog.Logger) (*ConsumerGroup, error) {
	if numConsumers < 1 {
		return nil, errors.New("kafka: at least one consumer is required")
	}

	cg := &ConsumerGroup{
		consumers: make([]*Consumer, 0, numConsumers),
		config:    config,
		logger:    logger,
		handler:   handler,
	}

	for i := 0; i < numConsumers; i++ {
		consumer, err := NewConsumer(config, handler, logger.With("consumer_id", i))
		if err != nil {
			// Clean up already created consumers
			for _, c := range cg.consumers {
				c.Stop()
			}
			return nil, fmt.Errorf("kafka: failed to create consumer %d: %w", i, err)
		}
		cg.consumers = append(cg.consumers, consumer)
	}

	return cg, nil
}

// Start starts all consumers in the group.
func (cg *ConsumerGroup) Start() error {
	cg.mu.Lock()
	defer cg.mu.Unlock()

	if cg.started {
		return errors.New("kafka: consumer group already started")
	}

	for i, c := range cg.consumers {
		if err := c.StartAsync(); err != nil {
			// Stop already started consumers
			for j := 0; j < i; j++ {
				cg.consumers[j].Stop()
			}
			return fmt.Errorf("kafka: failed to start consumer %d: %w", i, err)
		}
	}

	cg.started = true
	cg.logger.Info("consumer group started",
		"num_consumers", len(cg.consumers),
		"topic", cg.config.Topic,
		"group", cg.config.ConsumerGroup,
	)

	return nil
}

// Stop stops all consumers in the group.
func (cg *ConsumerGroup) Stop() error {
	cg.mu.Lock()
	defer cg.mu.Unlock()

	var errs []error
	for i, c := range cg.consumers {
		if err := c.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("consumer %d: %w", i, err))
		}
	}

	cg.started = false

	if len(errs) > 0 {
		return fmt.Errorf("kafka: errors stopping consumers: %v", errs)
	}

	return nil
}

// GetMetrics returns aggregated metrics from all consumers.
func (cg *ConsumerGroup) GetMetrics() Metrics {
	var m Metrics
	for _, c := range cg.consumers {
		cm := c.GetMetrics()
		m.MessagesConsumed += cm.MessagesConsumed
		m.BytesConsumed += cm.BytesConsumed
		m.Errors += cm.Errors
	}
	return m
}
