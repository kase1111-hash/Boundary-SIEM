// Package consumer moves events from the ingest queue to their destinations:
// storage (a blocking writer that applies backpressure) and any number of
// non-blocking sinks such as the correlation engine.
package consumer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
	"boundary-siem/internal/storage"
)

// ErrDrainTimeout is returned by Drain when the queue could not be emptied
// in time. The error message says how many events were left behind.
var ErrDrainTimeout = errors.New("consumer: queue not drained before the deadline")

// maxPollWait caps how long a worker waits for an event before it checks
// whether it was told to stop, so Drain never waits on a parked worker.
const maxPollWait = 100 * time.Millisecond

// Config holds the consumer configuration.
type Config struct {
	Workers      int           `yaml:"workers"`
	PollInterval time.Duration `yaml:"poll_interval"`
	// ShutdownWait bounds Drain (and Stop) in addition to the context the
	// caller passes.
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

// EventWriter is the storage destination of the consumer. Write may block
// (backpressure). It is satisfied by *storage.BatchWriter.
type EventWriter interface {
	Write(event *schema.Event) error
	Flush() error
}

// EventSink is a secondary destination that must never slow ingestion down:
// Offer returns at once and reports whether the sink accepted the event.
// AsyncSink is the implementation used for the correlation engine.
type EventSink interface {
	Offer(event *schema.Event) bool
}

// eventWriter is kept as an alias so existing tests can build a Consumer
// literal with an in-memory writer.
type eventWriter = EventWriter

// Option configures a Consumer.
type Option func(*Consumer)

// WithWriter sets the storage writer. Without one events are only handed to
// the sinks (development mode without storage).
func WithWriter(w EventWriter) Option {
	return func(c *Consumer) { c.batchWriter = w }
}

// WithSink adds a non-blocking destination that receives every event before
// it is written to storage.
func WithSink(s EventSink) Option {
	return func(c *Consumer) { c.sinks = append(c.sinks, s) }
}

// Consumer reads events from the queue and delivers them to the storage
// writer and the sinks.
//
// Shutdown: Drain (or Stop) tells the workers to finish. They keep popping
// until the queue is empty (or closed and empty), so every event that was
// accepted into the queue is delivered. Callers should stop the producers
// and Close the queue first, so nothing is pushed while the queue drains.
type Consumer struct {
	queue       *queue.RingBuffer
	batchWriter eventWriter
	sinks       []EventSink
	config      Config

	wg         sync.WaitGroup
	done       chan struct{} // closed by Drain: drain the queue and exit
	abort      chan struct{} // closed when Drain gives up: exit at once
	stopOnce   sync.Once
	abortOnce  sync.Once // creates abort
	abortClose sync.Once // closes abort

	// Metrics
	consumed      uint64
	errors        uint64
	flushFailures uint64
}

// New creates a Consumer that writes to the given batch writer. A nil bw
// means no storage writer.
func New(q *queue.RingBuffer, bw *storage.BatchWriter, cfg Config) *Consumer {
	var opts []Option
	if bw != nil {
		opts = append(opts, WithWriter(bw))
	}
	return NewConsumer(q, cfg, opts...)
}

// NewConsumer creates a Consumer. Zero or negative Workers, PollInterval and
// ShutdownWait are replaced by the DefaultConfig values.
func NewConsumer(q *queue.RingBuffer, cfg Config, opts ...Option) *Consumer {
	defaults := DefaultConfig()
	if cfg.Workers <= 0 {
		cfg.Workers = defaults.Workers
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaults.PollInterval
	}
	if cfg.ShutdownWait <= 0 {
		cfg.ShutdownWait = defaults.ShutdownWait
	}
	c := &Consumer{
		queue:  q,
		config: cfg,
		done:   make(chan struct{}),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// abortCh returns the abort channel, creating it on first use so Consumer
// literals built without NewConsumer work too.
func (c *Consumer) abortCh() chan struct{} {
	c.abortOnce.Do(func() {
		if c.abort == nil {
			c.abort = make(chan struct{})
		}
	})
	return c.abort
}

// Start starts the consumer workers. Cancelling ctx makes the workers drain
// the queue and exit, like Drain.
func (c *Consumer) Start(ctx context.Context) {
	abort := c.abortCh()
	for i := 0; i < c.config.Workers; i++ {
		c.wg.Add(1)
		go c.worker(ctx, i, abort)
	}

	slog.Info("queue consumer started",
		"workers", c.config.Workers,
		"storage", c.batchWriter != nil,
		"sinks", len(c.sinks),
	)
}

// worker is a single consumer worker goroutine.
func (c *Consumer) worker(ctx context.Context, id int, abort <-chan struct{}) {
	defer c.wg.Done()

	slog.Debug("consumer worker started", "worker_id", id)

	for {
		select {
		case <-abort:
			return
		case <-c.done:
			c.drain(id, abort)
			return
		case <-ctx.Done():
			c.drain(id, abort)
			return
		default:
		}

		event, err := c.queue.PopWithTimeout(min(c.config.PollInterval, maxPollWait))
		switch {
		case err == nil:
			c.handle(id, event)
		case errors.Is(err, queue.ErrQueueEmpty):
			// idle
		case errors.Is(err, queue.ErrQueueClosed):
			// Closed and empty: nothing more will arrive.
			slog.Debug("consumer worker stopping (queue closed)", "worker_id", id)
			return
		default:
			slog.Warn("unexpected queue error", "worker_id", id, "error", err)
			atomic.AddUint64(&c.errors, 1)
		}
	}
}

// drain delivers what is left in the queue without waiting for new events.
func (c *Consumer) drain(id int, abort <-chan struct{}) {
	for {
		select {
		case <-abort:
			return
		default:
		}
		event, err := c.queue.Pop()
		if err != nil {
			slog.Debug("consumer worker drained", "worker_id", id)
			return
		}
		c.handle(id, event)
	}
}

// handle delivers one event: first to the sinks, which never block, then to
// storage.
func (c *Consumer) handle(id int, event *schema.Event) {
	for _, sink := range c.sinks {
		sink.Offer(event)
	}

	if c.batchWriter == nil {
		atomic.AddUint64(&c.consumed, 1)
		return
	}

	err := c.batchWriter.Write(event)
	switch {
	case err == nil:
		atomic.AddUint64(&c.consumed, 1)
	case errors.Is(err, storage.ErrBatchInsertFailed):
		// A flush triggered by this write failed. The writer keeps the
		// events (requeued) or hands them to its dead-letter handler and
		// accounts for them in its own metrics, so the event is not lost
		// here.
		atomic.AddUint64(&c.consumed, 1)
		atomic.AddUint64(&c.flushFailures, 1)
		slog.Warn("storage flush failed", "worker_id", id, "error", err)
	default:
		slog.Error("failed to write event",
			"worker_id", id,
			"event_id", event.EventID,
			"error", err,
		)
		atomic.AddUint64(&c.errors, 1)
	}
}

// Stop drains the queue and stops the workers, waiting at most ShutdownWait.
func (c *Consumer) Stop() {
	if err := c.Drain(context.Background()); err != nil {
		slog.Error("queue consumer stop", "error", err)
	}
}

// Drain makes the workers deliver every event still in the queue and exit,
// then flushes the storage writer. It waits until that is done, ctx is done
// or ShutdownWait has passed, whichever comes first. If it gives up, the
// workers are told to stop at once and the returned error (wrapping
// ErrDrainTimeout) says how many events were left in the queue, or that the
// queue was empty and a storage write was still running.
func (c *Consumer) Drain(ctx context.Context) error {
	c.stopOnce.Do(func() { close(c.done) })

	wait := c.config.ShutdownWait
	if wait <= 0 {
		wait = DefaultConfig().ShutdownWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	finished := make(chan struct{})
	go func() {
		c.wg.Wait()
		if c.batchWriter != nil {
			if err := c.batchWriter.Flush(); err != nil {
				slog.Error("final flush failed", "error", err)
			}
		}
		close(finished)
	}()

	select {
	case <-finished:
		slog.Info("queue consumer drained",
			"consumed", atomic.LoadUint64(&c.consumed),
			"errors", atomic.LoadUint64(&c.errors),
		)
		return nil
	case <-ctx.Done():
	case <-timer.C:
	}

	abort := c.abortCh()
	c.abortClose.Do(func() { close(abort) })
	remaining := c.queue.Len()
	if remaining > 0 {
		slog.Error("queue consumer did not drain the queue in time; events left in the queue are not stored",
			"remaining_events", remaining,
			"consumed", atomic.LoadUint64(&c.consumed),
		)
		return fmt.Errorf("%w: %d events left in the queue", ErrDrainTimeout, remaining)
	}
	// The queue is empty: the time went into storage writes (a flush
	// retrying against an unavailable ClickHouse, or the final flush). The
	// events they hold are still the writer's, which stores, dead-letters
	// or reports them as lost when it is closed.
	slog.Warn("queue consumer did not finish in time: the queue is empty but a storage write is still running",
		"consumed", atomic.LoadUint64(&c.consumed),
	)
	return fmt.Errorf("%w: queue empty, storage write still in progress", ErrDrainTimeout)
}

// Metrics returns consumer statistics.
func (c *Consumer) Metrics() ConsumerMetrics {
	return ConsumerMetrics{
		Consumed:      atomic.LoadUint64(&c.consumed),
		Errors:        atomic.LoadUint64(&c.errors),
		FlushFailures: atomic.LoadUint64(&c.flushFailures),
	}
}

// ConsumerMetrics holds consumer statistics.
type ConsumerMetrics struct {
	// Consumed counts events handed to storage (or, without storage, to the
	// sinks).
	Consumed uint64 `json:"consumed"`
	// Errors counts events the storage writer refused (for example after it
	// was closed); they are lost.
	Errors uint64 `json:"errors"`
	// FlushFailures counts writes whose triggered flush failed; the events
	// were kept by the writer and are not lost.
	FlushFailures uint64 `json:"flush_failures"`
}
