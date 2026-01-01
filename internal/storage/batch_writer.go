package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"boundary-siem/internal/schema"
)

// BatchWriterConfig holds configuration for the batch writer.
type BatchWriterConfig struct {
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	MaxRetries    int           `yaml:"max_retries"`
	RetryDelay    time.Duration `yaml:"retry_delay"`
}

// DefaultBatchWriterConfig returns the default batch writer configuration.
func DefaultBatchWriterConfig() BatchWriterConfig {
	return BatchWriterConfig{
		BatchSize:     1000,
		FlushInterval: 5 * time.Second,
		MaxRetries:    3,
		RetryDelay:    time.Second,
	}
}

// BatchWriter handles batched inserts to ClickHouse.
type BatchWriter struct {
	client *ClickHouseClient
	config BatchWriterConfig

	buffer []*schema.Event
	mu     sync.Mutex

	flushTimer *time.Timer
	done       chan struct{}
	closed     bool

	// Metrics
	totalWritten uint64
	totalFailed  uint64
	batchCount   uint64
}

// NewBatchWriter creates a new BatchWriter.
func NewBatchWriter(client *ClickHouseClient, cfg BatchWriterConfig) *BatchWriter {
	bw := &BatchWriter{
		client: client,
		config: cfg,
		buffer: make([]*schema.Event, 0, cfg.BatchSize),
		done:   make(chan struct{}),
	}

	// Start flush timer
	bw.flushTimer = time.AfterFunc(cfg.FlushInterval, bw.timerFlush)

	return bw
}

// Write adds an event to the batch.
func (bw *BatchWriter) Write(event *schema.Event) error {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	if bw.closed {
		return fmt.Errorf("batch writer is closed")
	}

	bw.buffer = append(bw.buffer, event)

	if len(bw.buffer) >= bw.config.BatchSize {
		return bw.flushLocked()
	}

	return nil
}

// timerFlush is called by the flush timer.
func (bw *BatchWriter) timerFlush() {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	if bw.closed {
		return
	}

	if len(bw.buffer) > 0 {
		if err := bw.flushLocked(); err != nil {
			slog.Error("timer flush failed", "error", err)
		}
	}

	// Reset timer
	bw.flushTimer.Reset(bw.config.FlushInterval)
}

// flushLocked flushes the buffer. Caller must hold the lock.
func (bw *BatchWriter) flushLocked() error {
	if len(bw.buffer) == 0 {
		return nil
	}

	events := bw.buffer
	bw.buffer = make([]*schema.Event, 0, bw.config.BatchSize)

	// Perform batch insert with retries
	var lastErr error
	for attempt := 0; attempt <= bw.config.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(bw.config.RetryDelay * time.Duration(attempt))
		}

		if err := bw.insertBatch(events); err != nil {
			lastErr = err
			slog.Warn("batch insert failed, retrying",
				"attempt", attempt+1,
				"max_retries", bw.config.MaxRetries,
				"error", err,
			)
			continue
		}

		atomic.AddUint64(&bw.totalWritten, uint64(len(events)))
		atomic.AddUint64(&bw.batchCount, 1)
		return nil
	}

	atomic.AddUint64(&bw.totalFailed, uint64(len(events)))
	return fmt.Errorf("batch insert failed after %d retries: %w", bw.config.MaxRetries, lastErr)
}

// insertBatch inserts a batch of events into ClickHouse.
func (bw *BatchWriter) insertBatch(events []*schema.Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	batch, err := bw.client.PrepareBatch(ctx, `
		INSERT INTO events (
			event_id, tenant_id, timestamp, received_at,
			source_product, source_host, source_instance_id, source_version,
			actor_type, actor_id, actor_name, actor_email, actor_ip,
			action, target, outcome, severity,
			schema_version, raw, metadata
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare batch: %w", err)
	}

	for _, event := range events {
		metadata, _ := json.Marshal(event.Metadata)

		// Handle actor fields
		actorType := "unknown"
		actorID := ""
		actorName := ""
		actorEmail := ""
		actorIP := ""

		if event.Actor != nil {
			if event.Actor.Type != "" {
				actorType = string(event.Actor.Type)
			}
			actorID = event.Actor.ID
			actorName = event.Actor.Name
			actorEmail = event.Actor.Email
			actorIP = event.Actor.IPAddress
		}

		// Handle tenant ID
		tenantID := event.TenantID
		if tenantID == "" {
			tenantID = "default"
		}

		err := batch.Append(
			event.EventID,
			tenantID,
			event.Timestamp,
			event.ReceivedAt,
			event.Source.Product,
			event.Source.Host,
			event.Source.InstanceID,
			event.Source.Version,
			actorType,
			actorID,
			actorName,
			actorEmail,
			actorIP,
			event.Action,
			event.Target,
			string(event.Outcome),
			uint8(event.Severity),
			event.SchemaVersion,
			event.Raw,
			string(metadata),
		)
		if err != nil {
			return fmt.Errorf("failed to append event: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("failed to send batch: %w", err)
	}

	slog.Debug("batch inserted", "count", len(events))
	return nil
}

// Flush forces a flush of the current buffer.
func (bw *BatchWriter) Flush() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return bw.flushLocked()
}

// Close closes the batch writer.
func (bw *BatchWriter) Close() error {
	bw.mu.Lock()
	bw.closed = true
	bw.mu.Unlock()

	bw.flushTimer.Stop()
	close(bw.done)

	// Final flush
	return bw.Flush()
}

// Metrics returns batch writer statistics.
func (bw *BatchWriter) Metrics() BatchWriterMetrics {
	return BatchWriterMetrics{
		Written: atomic.LoadUint64(&bw.totalWritten),
		Failed:  atomic.LoadUint64(&bw.totalFailed),
		Batches: atomic.LoadUint64(&bw.batchCount),
		Pending: bw.pendingCount(),
	}
}

func (bw *BatchWriter) pendingCount() int {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return len(bw.buffer)
}

// BatchWriterMetrics holds batch writer statistics.
type BatchWriterMetrics struct {
	Written uint64 `json:"written"`
	Failed  uint64 `json:"failed"`
	Batches uint64 `json:"batches"`
	Pending int    `json:"pending"`
}
