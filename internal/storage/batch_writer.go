package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"boundary-siem/internal/schema"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

// DefaultTenantID is the tenant stored for events that carry no tenant ID.
const DefaultTenantID = "default"

// DefaultMaxRequeues is the number of failed flushes an event survives when
// BatchWriterConfig.MaxRequeues is zero.
const DefaultMaxRequeues = 3

// ErrWriterClosed is returned by Write after Close.
var ErrWriterClosed = errors.New("batch writer is closed")

// BatchWriterConfig holds configuration for the batch writer.
type BatchWriterConfig struct {
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	MaxRetries    int           `yaml:"max_retries"`
	RetryDelay    time.Duration `yaml:"retry_delay"`

	// MaxPending bounds the events held in memory, including events put back
	// after a failed flush. Zero means 10 × BatchSize.
	MaxPending int `yaml:"max_pending"`

	// MaxRequeues is how many failed flushes (each already retried
	// MaxRetries times) an event survives before it is given up on. Zero
	// means DefaultMaxRequeues; a negative value gives up after the first
	// failed flush.
	MaxRequeues int `yaml:"max_requeues"`
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

// DeadLetterFunc receives events the BatchWriter has given up on, together
// with the insert error. It is called without the writer's lock held and must
// not call back into the writer. A nil return means the events are safe
// elsewhere (they are counted as dead-lettered); an error means they are
// lost (they are counted as dropped).
type DeadLetterFunc func(ctx context.Context, events []*schema.Event, cause error) error

// BatchWriterOption configures optional BatchWriter behaviour.
type BatchWriterOption func(*BatchWriter)

// WithDeadLetter sets the handler for events that cannot be written to the
// events table. QuarantineWriter.DeadLetter is a ready-made handler.
func WithDeadLetter(fn DeadLetterFunc) BatchWriterOption {
	return func(bw *BatchWriter) { bw.deadLetter = fn }
}

// pendingEvent is a buffered event and the number of failed flushes it has
// been part of.
type pendingEvent struct {
	event    *schema.Event
	requeues int

	// token is the insert_deduplication_token of the failed INSERT the event
	// was last part of, or "" before its first INSERT. The event is retried
	// under the same token, so when that INSERT was in fact committed (the
	// error came after the server had stored it) ClickHouse drops the repeat
	// instead of storing the events twice.
	token string
}

// BatchWriter handles batched inserts to ClickHouse.
//
// Failure handling: a batch insert is retried MaxRetries times with
// exponential backoff (RetryDelay, 2×RetryDelay, ...). If it still fails the
// events are put back at the front of the buffer and written with the next
// flush, so a ClickHouse outage shorter than MaxRequeues flushes loses
// nothing; while the buffer stays full every Write triggers a flush and
// blocks for its retries, which pushes back on the caller. An event is given
// up on when it has been part of more than MaxRequeues failed flushes, when
// the buffer would exceed MaxPending, or when the final flush in Close fails.
// Given-up events go to the dead-letter handler (WithDeadLetter) if one is
// set, and are otherwise dropped. Every failed flush returns an error wrapping
// ErrBatchInsertFailed that says how many events were requeued, dead-lettered
// and dropped, and the Metrics counters track the same numbers.
//
// Retries are idempotent: every INSERT carries an insert_deduplication_token,
// and the events of a failed INSERT are retried, within the flush and after a
// requeue, under that same token (the events table keeps a deduplication
// window, migration 007). An INSERT that failed only after the server had
// committed it is therefore not stored a second time.
type BatchWriter struct {
	client     *ClickHouseClient
	config     BatchWriterConfig
	deadLetter DeadLetterFunc

	buffer []pendingEvent
	mu     sync.Mutex

	// inflight counts flushes whose insert is running without mu held;
	// idle is signalled (under mu) whenever it drops.
	inflight int
	idle     *sync.Cond
	// inflightEvents counts the events of those flushes.
	inflightEvents int

	flushTimer *time.Timer
	done       chan struct{}
	closed     bool

	// Metrics
	totalWritten      uint64
	totalFailed       uint64
	totalDeadLettered uint64
	totalRequeued     uint64
	batchCount        uint64
}

// NewBatchWriter creates a new BatchWriter.
func NewBatchWriter(client *ClickHouseClient, cfg BatchWriterConfig, opts ...BatchWriterOption) *BatchWriter {
	bw := &BatchWriter{
		client: client,
		config: cfg,
		buffer: make([]pendingEvent, 0, max(cfg.BatchSize, 0)),
		done:   make(chan struct{}),
	}
	bw.idle = sync.NewCond(&bw.mu)
	for _, opt := range opts {
		opt(bw)
	}

	// Start flush timer
	bw.flushTimer = time.AfterFunc(bw.flushInterval(), bw.timerFlush)

	return bw
}

// batchSize returns the configured batch size, or the default when unset.
func (bw *BatchWriter) batchSize() int {
	if bw.config.BatchSize > 0 {
		return bw.config.BatchSize
	}
	return DefaultBatchWriterConfig().BatchSize
}

// flushInterval returns the configured flush interval, or the default when
// unset (a zero interval would make the timer spin).
func (bw *BatchWriter) flushInterval() time.Duration {
	if bw.config.FlushInterval > 0 {
		return bw.config.FlushInterval
	}
	return DefaultBatchWriterConfig().FlushInterval
}

// maxPending returns the in-memory event limit.
func (bw *BatchWriter) maxPending() int {
	if bw.config.MaxPending > 0 {
		return max(bw.config.MaxPending, bw.batchSize())
	}
	return 10 * bw.batchSize()
}

// maxRequeues returns how many failed flushes an event survives.
func (bw *BatchWriter) maxRequeues() int {
	switch {
	case bw.config.MaxRequeues > 0:
		return bw.config.MaxRequeues
	case bw.config.MaxRequeues < 0:
		return 0
	default:
		return DefaultMaxRequeues
	}
}

// Write adds an event to the batch. When the buffer reaches BatchSize the
// batch is flushed in the calling goroutine and the flush error, if any, is
// returned; the event itself is kept for a later flush unless the error says
// it was dead-lettered or dropped.
func (bw *BatchWriter) Write(event *schema.Event) error {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	if bw.closed {
		return ErrWriterClosed
	}

	bw.buffer = append(bw.buffer, pendingEvent{event: event})

	if len(bw.buffer) >= bw.batchSize() {
		return bw.flushLocked(false)
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
		if err := bw.flushLocked(false); err != nil {
			slog.Error("timer flush failed", "error", err)
		}
	}

	// flushLocked releases the lock, so Close may have run meanwhile.
	if !bw.closed {
		bw.flushTimer.Reset(bw.flushInterval())
	}
}

// flushLocked flushes the buffer. Caller must hold the lock.
// The lock is released during the insert and its retries so Write() is not
// blocked. With final set, failed events are given up on instead of being
// requeued.
func (bw *BatchWriter) flushLocked(final bool) error {
	if len(bw.buffer) == 0 {
		return nil
	}

	pending := bw.buffer
	bw.buffer = make([]pendingEvent, 0, bw.batchSize())
	bw.inflight++
	bw.inflightEvents += len(pending)

	bw.mu.Unlock()
	failed, insertErr := bw.insertPending(pending)
	bw.mu.Lock()
	bw.inflightEvents -= len(pending)

	var err error
	if len(failed) > 0 {
		giveUp, requeued := bw.requeueLocked(failed, final)

		// Hand given-up events to the dead-letter handler without the lock.
		bw.mu.Unlock()
		deadLettered, dropped := bw.giveUp(giveUp, insertErr)
		bw.mu.Lock()

		err = NewStorageErrorWithRetries("BatchInsert", "events",
			fmt.Errorf("%w: %d events requeued, %d dead-lettered, %d dropped: %v",
				ErrBatchInsertFailed, requeued, deadLettered, dropped, insertErr),
			bw.config.MaxRetries)
	}

	bw.inflight--
	bw.idle.Broadcast()
	return err
}

// requeueLocked puts the events of a failed batch back at the front of the
// buffer and returns the events to give up on and the number requeued.
// Caller must hold the lock.
func (bw *BatchWriter) requeueLocked(failed []pendingEvent, final bool) ([]*schema.Event, int) {
	var giveUp []*schema.Event
	keep := make([]pendingEvent, 0, len(failed)+len(bw.buffer))
	for _, p := range failed {
		p.requeues++
		if final || p.requeues > bw.maxRequeues() {
			giveUp = append(giveUp, p.event)
			continue
		}
		keep = append(keep, p)
	}
	requeued := len(keep)

	// Events written while the insert ran go after the requeued ones, so the
	// buffer stays in arrival order. Past MaxPending the oldest are given up.
	keep = append(keep, bw.buffer...)
	if over := len(keep) - bw.maxPending(); over > 0 {
		giveUp = append(giveUp, eventsOf(keep[:over])...)
		requeued -= min(over, requeued)
		keep = keep[over:]
	}
	bw.buffer = keep

	atomic.AddUint64(&bw.totalRequeued, uint64(requeued))
	return giveUp, requeued
}

// giveUp hands events that will not be written to the events table to the
// dead-letter handler, or drops them, and returns how many went each way.
// Must NOT be called with the mutex held.
func (bw *BatchWriter) giveUp(events []*schema.Event, cause error) (deadLettered, dropped int) {
	if len(events) == 0 {
		return 0, 0
	}
	atomic.AddUint64(&bw.totalFailed, uint64(len(events)))

	if bw.deadLetter != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := bw.deadLetter(ctx, events, cause)
		cancel()
		if err == nil {
			atomic.AddUint64(&bw.totalDeadLettered, uint64(len(events)))
			slog.Warn("events dead-lettered after failed batch inserts",
				"count", len(events), "error", cause)
			return len(events), 0
		}
		slog.Error("dead-letter handler failed", "count", len(events), "error", err)
	}

	slog.Error("events dropped after failed batch inserts",
		"count", len(events), "error", cause)
	return 0, len(events)
}

// eventsOf returns the events of a pending slice.
func eventsOf(pending []pendingEvent) []*schema.Event {
	events := make([]*schema.Event, len(pending))
	for i, p := range pending {
		events[i] = p.event
	}
	return events
}

// insertGroup is the events of one INSERT and its deduplication token.
type insertGroup struct {
	token  string
	events []pendingEvent
}

// insertGroups splits pending events into INSERTs: the events of each earlier
// failed INSERT form a group under that INSERT's token, and events not yet
// attempted form one group under a fresh token. Groups are in the order of
// their first event.
func insertGroups(pending []pendingEvent) []insertGroup {
	var groups []insertGroup
	index := make(map[string]int)
	for _, p := range pending {
		i, ok := index[p.token]
		if !ok {
			i = len(groups)
			index[p.token] = i
			token := p.token
			if token == "" {
				token = uuid.NewString()
			}
			groups = append(groups, insertGroup{token: token})
		}
		groups[i].events = append(groups[i].events, p)
	}
	return groups
}

// insertPending inserts pending events, one INSERT (with retries) per
// insertGroup, and returns the events that were not inserted, each tagged
// with the token of its failed INSERT, and the insert error. Once a group has
// failed, the remaining groups are not attempted (ClickHouse is most likely
// unavailable) and are returned as failed with their tokens unchanged. Must
// NOT be called with the mutex held.
func (bw *BatchWriter) insertPending(pending []pendingEvent) ([]pendingEvent, error) {
	var failed []pendingEvent
	var insertErr error
	for _, g := range insertGroups(pending) {
		if insertErr == nil {
			insertErr = bw.insertBatchWithRetries(eventsOf(g.events), g.token)
			if insertErr == nil {
				continue
			}
			for i := range g.events {
				g.events[i].token = g.token
			}
		}
		failed = append(failed, g.events...)
	}
	return failed, insertErr
}

// insertBatchWithRetries attempts to insert a batch with exponential backoff,
// every attempt under the same deduplication token. The insert is always
// attempted at least once, even if MaxRetries is negative: a loop that never
// ran would report success for a batch that was never written. Must NOT be
// called with the mutex held.
func (bw *BatchWriter) insertBatchWithRetries(events []*schema.Event, token string) error {
	var lastErr error
	for attempt := 0; attempt <= max(bw.config.MaxRetries, 0); attempt++ {
		if attempt > 0 {
			time.Sleep(bw.config.RetryDelay * time.Duration(1<<(attempt-1)))
		}

		if err := bw.insertBatch(events, token); err != nil {
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

	return lastErr
}

// insertTimeout bounds one INSERT attempt.
const insertTimeout = 30 * time.Second

// insertBatch inserts a batch of events into ClickHouse as one INSERT with
// the given insert_deduplication_token.
func (bw *BatchWriter) insertBatch(events []*schema.Event, token string) error {
	ctx, cancel := context.WithTimeout(insertContext(token), insertTimeout)
	defer cancel()

	batch, err := bw.client.PrepareBatch(ctx, `
		INSERT INTO events (
			event_id, tenant_id, timestamp, received_at,
			source_product, source_host, source_instance_id, source_version,
			actor_type, actor_id, actor_name, actor_email, actor_ip,
			action, target, outcome, severity,
			schema_version, request_id, raw, metadata
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare batch: %w", err)
	}
	// Release the connection if Send is never reached; a no-op after Send.
	defer func() { _ = batch.Close() }()

	for _, event := range events {
		metadata, err := json.Marshal(event.Metadata)
		if err != nil {
			slog.Warn("failed to marshal event metadata, using empty object",
				"event_id", event.EventID,
				"error", err,
			)
			metadata = []byte("{}")
		}

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
			tenantID = DefaultTenantID
		}

		err = batch.Append(
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
			severityToUInt8(event.Severity),
			event.SchemaVersion,
			event.RequestID,
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

// insertContext returns the base context of an INSERT into events. It sets
// insert_deduplication_token, so the server drops a repeat of an INSERT it
// has already stored, and extends that to the blocks events_critical_mv
// writes to events_critical (see migration 007). The SummingMergeTree inside
// events_hourly_mv has no deduplication window and still counts a repeat.
func insertContext(token string) context.Context {
	return clickhouse.Context(context.Background(), clickhouse.WithSettings(clickhouse.Settings{
		"insert_deduplication_token":                         token,
		"deduplicate_blocks_in_dependent_materialized_views": 1,
	}))
}

// severityToUInt8 converts an event severity to the UInt8 severity column.
// Validated events are always within 1-10, but events reaching the writer
// without validation are clamped so they cannot wrap (e.g. 256 -> 0, -1 -> 255).
func severityToUInt8(severity int) uint8 {
	if severity < 0 {
		return 0
	}
	if severity > math.MaxUint8 {
		return math.MaxUint8
	}
	return uint8(severity)
}

// Flush forces a flush of the current buffer. Events of a failed flush are
// requeued as described on BatchWriter, except after Close, when nothing
// would flush them again and they are given up on instead.
func (bw *BatchWriter) Flush() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return bw.flushLocked(bw.closed)
}

// Close stops the writer: it rejects further writes, waits for flushes that
// are in flight (including timer flushes), and then writes whatever is still
// buffered. Events that the final flush cannot write are dead-lettered or
// dropped, and the returned error says how many. Close is idempotent.
func (bw *BatchWriter) Close() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	if !bw.closed {
		bw.closed = true
		bw.flushTimer.Stop()
		close(bw.done)
	}

	for bw.inflight > 0 {
		bw.idle.Wait()
	}

	// Final flush
	return bw.flushLocked(true)
}

// Metrics returns batch writer statistics.
func (bw *BatchWriter) Metrics() BatchWriterMetrics {
	return BatchWriterMetrics{
		Written:      atomic.LoadUint64(&bw.totalWritten),
		Failed:       atomic.LoadUint64(&bw.totalFailed),
		DeadLettered: atomic.LoadUint64(&bw.totalDeadLettered),
		Requeued:     atomic.LoadUint64(&bw.totalRequeued),
		Batches:      atomic.LoadUint64(&bw.batchCount),
		Pending:      bw.pendingCount(),
	}
}

// pendingCount returns the events the writer holds: buffered, or in a flush
// that has not finished (an insert still retrying against an unavailable
// server included).
func (bw *BatchWriter) pendingCount() int {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return len(bw.buffer) + bw.inflightEvents
}

// BatchWriterMetrics holds batch writer statistics.
type BatchWriterMetrics struct {
	// Written is the number of events stored in the events table.
	Written uint64 `json:"written"`
	// Failed is the number of events given up on: not stored in the events
	// table. It includes the dead-lettered ones; Failed - DeadLettered
	// events were lost.
	Failed uint64 `json:"failed"`
	// DeadLettered is the number of given-up events the dead-letter handler
	// accepted.
	DeadLettered uint64 `json:"dead_lettered"`
	// Requeued counts events put back into the buffer after a failed flush
	// (an event requeued twice counts twice).
	Requeued uint64 `json:"requeued"`
	Batches  uint64 `json:"batches"`
	// Pending is the number of events the writer holds and has neither
	// written nor given up on: buffered, or in a flush that is still running
	// (including its retries).
	Pending int `json:"pending"`
}
