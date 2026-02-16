// Package consumer provides a queue consumer that writes events to storage.
package consumer

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"boundary-siem/internal/queue"
	"boundary-siem/internal/storage"
)

// Config holds the consumer configuration.
type Config struct {
	Workers      int           `yaml:"workers"`
	PollInterval time.Duration `yaml:"poll_interval"`
	ShutdownWait time.Duration `yaml:"shutdown_wait"`
}

// DefaultConfig returns the default consumer configuration.
func DefaultConfig() Config {
	return Config{
		Workers:      4,
		PollInterval: 10 * time.Millisecond,
		ShutdownWait: 30 * time.Second,
	}
}

// Consumer reads events from the queue and writes them to storage.
type Consumer struct {
	queue       *queue.RingBuffer
	batchWriter *storage.BatchWriter
	config      Config

	wg   sync.WaitGroup
	done chan struct{}

	// Metrics
	consumed uint64
	errors   uint64
}

// New creates a new Consumer.
func New(q *queue.RingBuffer, bw *storage.BatchWriter, cfg Config) *Consumer {
	return &Consumer{
		queue:       q,
		batchWriter: bw,
		config:      cfg,
		done:        make(chan struct{}),
	}
}

// Start starts the consumer workers.
func (c *Consumer) Start(ctx context.Context) {
	for i := 0; i < c.config.Workers; i++ {
		c.wg.Add(1)
		go c.worker(ctx, i)
	}

	slog.Info("queue consumer started", "workers", c.config.Workers)
}

// worker is a single consumer worker goroutine.
func (c *Consumer) worker(ctx context.Context, id int) {
	defer c.wg.Done()

	slog.Debug("consumer worker started", "worker_id", id)

	for {
		select {
		case <-ctx.Done():
			slog.Debug("consumer worker stopping (context)", "worker_id", id)
			return
		case <-c.done:
			slog.Debug("consumer worker stopping (done)", "worker_id", id)
			return
		default:
			event, err := c.queue.PopWithTimeout(c.config.PollInterval)
			if err != nil {
				if err == queue.ErrQueueEmpty {
					continue
				}
				if err == queue.ErrQueueClosed {
					return
				}
				slog.Warn("unexpected queue error", "worker_id", id, "error", err)
				atomic.AddUint64(&c.errors, 1)
				continue
			}

			if err := c.batchWriter.Write(event); err != nil {
				slog.Error("failed to write event",
					"worker_id", id,
					"event_id", event.EventID,
					"error", err,
				)
				atomic.AddUint64(&c.errors, 1)
				continue
			}

			atomic.AddUint64(&c.consumed, 1)
		}
	}
}

// Stop stops the consumer gracefully.
func (c *Consumer) Stop() {
	close(c.done)

	// Wait for workers with timeout
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("queue consumer stopped gracefully")
	case <-time.After(c.config.ShutdownWait):
		slog.Warn("queue consumer shutdown timed out")
	}

	// Final flush
	if err := c.batchWriter.Flush(); err != nil {
		slog.Error("final flush failed", "error", err)
	}
}

// Metrics returns consumer statistics.
func (c *Consumer) Metrics() ConsumerMetrics {
	return ConsumerMetrics{
		Consumed: atomic.LoadUint64(&c.consumed),
		Errors:   atomic.LoadUint64(&c.errors),
	}
}

// ConsumerMetrics holds consumer statistics.
type ConsumerMetrics struct {
	Consumed uint64 `json:"consumed"`
	Errors   uint64 `json:"errors"`
}
