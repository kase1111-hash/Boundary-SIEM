package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"boundary-siem/internal/schema"

	"github.com/ClickHouse/clickhouse-go/v2/lib/column"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Mock implementations of driver.Conn and driver.Batch for unit testing
// without a real ClickHouse connection.
// ---------------------------------------------------------------------------

type mockConn struct {
	prepareBatchFunc func(ctx context.Context, query string, opts ...driver.PrepareBatchOption) (driver.Batch, error)
}

func (m *mockConn) Contributors() []string                                           { return nil }
func (m *mockConn) ServerVersion() (*driver.ServerVersion, error)                    { return nil, nil }
func (m *mockConn) Select(_ context.Context, _ any, _ string, _ ...any) error        { return nil }
func (m *mockConn) Query(_ context.Context, _ string, _ ...any) (driver.Rows, error) { return nil, nil }
func (m *mockConn) QueryRow(_ context.Context, _ string, _ ...any) driver.Row        { return nil }
func (m *mockConn) Exec(_ context.Context, _ string, _ ...any) error                 { return nil }
func (m *mockConn) AsyncInsert(_ context.Context, _ string, _ bool, _ ...any) error  { return nil }
func (m *mockConn) Ping(_ context.Context) error                                     { return nil }
func (m *mockConn) Stats() driver.Stats                                              { return driver.Stats{} }
func (m *mockConn) Close() error                                                     { return nil }

func (m *mockConn) PrepareBatch(ctx context.Context, query string, opts ...driver.PrepareBatchOption) (driver.Batch, error) {
	if m.prepareBatchFunc != nil {
		return m.prepareBatchFunc(ctx, query, opts...)
	}
	return &mockBatch{}, nil
}

type mockBatch struct {
	mu          sync.Mutex
	appendCount int
	sendFunc    func() error
}

func (m *mockBatch) Abort() error { return nil }
func (m *mockBatch) Append(_ ...any) error {
	m.mu.Lock()
	m.appendCount++
	m.mu.Unlock()
	return nil
}
func (m *mockBatch) AppendStruct(_ any) error        { return nil }
func (m *mockBatch) Column(_ int) driver.BatchColumn { return nil }
func (m *mockBatch) Flush() error                    { return nil }
func (m *mockBatch) Send() error {
	if m.sendFunc != nil {
		return m.sendFunc()
	}
	return nil
}
func (m *mockBatch) IsSent() bool                { return false }
func (m *mockBatch) Rows() int                   { return m.appendCount }
func (m *mockBatch) Columns() []column.Interface { return nil }
func (m *mockBatch) Close() error                { return nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestEvent() *schema.Event {
	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     time.Now(),
		ReceivedAt:    time.Now(),
		Source:        schema.Source{Product: "test-product", Host: "test-host"},
		Action:        "test.action",
		Outcome:       schema.OutcomeSuccess,
		Severity:      5,
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      "test-tenant",
		Raw:           `{"raw":"data"}`,
		Metadata:      map[string]any{"key": "value"},
	}
}

func newMockClient(conn driver.Conn) *ClickHouseClient {
	return &ClickHouseClient{
		conn:   conn,
		config: DefaultClickHouseConfig(),
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDefaultBatchWriterConfig(t *testing.T) {
	cfg := DefaultBatchWriterConfig()

	if cfg.BatchSize != 1000 {
		t.Errorf("BatchSize = %d, want 1000", cfg.BatchSize)
	}
	if cfg.FlushInterval != 5*time.Second {
		t.Errorf("FlushInterval = %v, want 5s", cfg.FlushInterval)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", cfg.MaxRetries)
	}
	if cfg.RetryDelay != time.Second {
		t.Errorf("RetryDelay = %v, want 1s", cfg.RetryDelay)
	}
}

func TestNewBatchWriter(t *testing.T) {
	cfg := DefaultBatchWriterConfig()
	client := newMockClient(&mockConn{})
	bw := NewBatchWriter(client, cfg)
	defer bw.Close()

	if bw.client != client {
		t.Error("client not set correctly")
	}
	if bw.config != cfg {
		t.Error("config not set correctly")
	}
	if len(bw.buffer) != 0 {
		t.Errorf("initial buffer length = %d, want 0", len(bw.buffer))
	}
	if cap(bw.buffer) != cfg.BatchSize {
		t.Errorf("initial buffer capacity = %d, want %d", cap(bw.buffer), cfg.BatchSize)
	}
	if bw.closed {
		t.Error("new writer should not be closed")
	}
	if bw.done == nil {
		t.Error("done channel should be initialized")
	}
	if bw.flushTimer == nil {
		t.Error("flush timer should be initialized")
	}

	metrics := bw.Metrics()
	if metrics.Written != 0 || metrics.Failed != 0 || metrics.Batches != 0 || metrics.Pending != 0 {
		t.Errorf("initial metrics should all be zero, got %+v", metrics)
	}
}

func TestBatchWriterWriteBuffersEvents(t *testing.T) {
	cfg := BatchWriterConfig{
		BatchSize:     100, // large enough so writes do not trigger a flush
		FlushInterval: time.Hour,
		MaxRetries:    0,
		RetryDelay:    time.Millisecond,
	}
	client := newMockClient(&mockConn{})
	bw := NewBatchWriter(client, cfg)
	defer bw.Close()

	for i := 0; i < 5; i++ {
		if err := bw.Write(newTestEvent()); err != nil {
			t.Fatalf("Write() error on event %d: %v", i, err)
		}
	}

	metrics := bw.Metrics()
	if metrics.Pending != 5 {
		t.Errorf("Pending = %d, want 5", metrics.Pending)
	}
	if metrics.Written != 0 {
		t.Errorf("Written = %d, want 0 (no flush triggered yet)", metrics.Written)
	}
	if metrics.Batches != 0 {
		t.Errorf("Batches = %d, want 0", metrics.Batches)
	}
}

func TestBatchWriterWriteWhenClosed(t *testing.T) {
	cfg := DefaultBatchWriterConfig()
	client := newMockClient(&mockConn{})
	bw := NewBatchWriter(client, cfg)

	if err := bw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	err := bw.Write(newTestEvent())
	if err == nil {
		t.Error("Write() after Close() should return an error")
	}
}

func TestBatchWriterFlushOnBatchSize(t *testing.T) {
	batchSize := 5
	cfg := BatchWriterConfig{
		BatchSize:     batchSize,
		FlushInterval: time.Hour, // long interval to prevent timer flush
		MaxRetries:    0,
		RetryDelay:    time.Millisecond,
	}

	batch := &mockBatch{}
	conn := &mockConn{
		prepareBatchFunc: func(_ context.Context, _ string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
			return batch, nil
		},
	}
	client := newMockClient(conn)
	bw := NewBatchWriter(client, cfg)
	defer bw.Close()

	// Write exactly batchSize events; the last write should trigger flushLocked.
	for i := 0; i < batchSize; i++ {
		if err := bw.Write(newTestEvent()); err != nil {
			t.Fatalf("Write() error on event %d: %v", i, err)
		}
	}

	metrics := bw.Metrics()
	if metrics.Pending != 0 {
		t.Errorf("Pending = %d, want 0 after flush", metrics.Pending)
	}
	if metrics.Written != uint64(batchSize) {
		t.Errorf("Written = %d, want %d", metrics.Written, batchSize)
	}
	if metrics.Batches != 1 {
		t.Errorf("Batches = %d, want 1", metrics.Batches)
	}
	if batch.appendCount != batchSize {
		t.Errorf("batch.appendCount = %d, want %d", batch.appendCount, batchSize)
	}
}

func TestBatchWriterMultipleBatchFlushes(t *testing.T) {
	batchSize := 3
	cfg := BatchWriterConfig{
		BatchSize:     batchSize,
		FlushInterval: time.Hour,
		MaxRetries:    0,
		RetryDelay:    time.Millisecond,
	}

	conn := &mockConn{
		prepareBatchFunc: func(_ context.Context, _ string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
			return &mockBatch{}, nil
		},
	}
	client := newMockClient(conn)
	bw := NewBatchWriter(client, cfg)
	defer bw.Close()

	totalEvents := batchSize * 4 // exactly 4 batches
	for i := 0; i < totalEvents; i++ {
		if err := bw.Write(newTestEvent()); err != nil {
			t.Fatalf("Write() error on event %d: %v", i, err)
		}
	}

	metrics := bw.Metrics()
	if metrics.Written != uint64(totalEvents) {
		t.Errorf("Written = %d, want %d", metrics.Written, totalEvents)
	}
	if metrics.Batches != 4 {
		t.Errorf("Batches = %d, want 4", metrics.Batches)
	}
	if metrics.Pending != 0 {
		t.Errorf("Pending = %d, want 0", metrics.Pending)
	}
}

func TestBatchWriterCloseFlushesBuffer(t *testing.T) {
	cfg := BatchWriterConfig{
		BatchSize:     100,
		FlushInterval: time.Hour,
		MaxRetries:    0,
		RetryDelay:    time.Millisecond,
	}

	var sendCalled atomic.Bool
	conn := &mockConn{
		prepareBatchFunc: func(_ context.Context, _ string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
			return &mockBatch{
				sendFunc: func() error {
					sendCalled.Store(true)
					return nil
				},
			}, nil
		},
	}
	client := newMockClient(conn)
	bw := NewBatchWriter(client, cfg)

	// Buffer some events (fewer than BatchSize so no automatic flush).
	for i := 0; i < 3; i++ {
		if err := bw.Write(newTestEvent()); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}

	// Verify events are pending before close.
	if bw.Metrics().Pending != 3 {
		t.Fatalf("Pending before close = %d, want 3", bw.Metrics().Pending)
	}

	if err := bw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if !sendCalled.Load() {
		t.Error("Close() should have flushed buffered events (batch Send was not called)")
	}

	metrics := bw.Metrics()
	if metrics.Written != 3 {
		t.Errorf("Written = %d, want 3 after close flush", metrics.Written)
	}
	if metrics.Pending != 0 {
		t.Errorf("Pending = %d, want 0 after close", metrics.Pending)
	}
}

func TestBatchWriterCloseWithEmptyBuffer(t *testing.T) {
	cfg := DefaultBatchWriterConfig()
	client := newMockClient(&mockConn{})
	bw := NewBatchWriter(client, cfg)

	if err := bw.Close(); err != nil {
		t.Fatalf("Close() with empty buffer error = %v", err)
	}

	metrics := bw.Metrics()
	if metrics.Written != 0 {
		t.Errorf("Written = %d, want 0", metrics.Written)
	}
	if metrics.Batches != 0 {
		t.Errorf("Batches = %d, want 0", metrics.Batches)
	}
}

func TestBatchWriterMetrics(t *testing.T) {
	cfg := DefaultBatchWriterConfig()
	client := newMockClient(&mockConn{})
	bw := NewBatchWriter(client, cfg)
	defer bw.Close()

	// Verify initial state.
	metrics := bw.Metrics()
	if metrics.Written != 0 || metrics.Failed != 0 || metrics.Batches != 0 || metrics.Pending != 0 {
		t.Errorf("initial metrics should all be zero, got %+v", metrics)
	}

	// Set atomic counters directly (same package, so fields are accessible).
	atomic.StoreUint64(&bw.totalWritten, 500)
	atomic.StoreUint64(&bw.totalFailed, 10)
	atomic.StoreUint64(&bw.batchCount, 5)

	metrics = bw.Metrics()
	if metrics.Written != 500 {
		t.Errorf("Written = %d, want 500", metrics.Written)
	}
	if metrics.Failed != 10 {
		t.Errorf("Failed = %d, want 10", metrics.Failed)
	}
	if metrics.Batches != 5 {
		t.Errorf("Batches = %d, want 5", metrics.Batches)
	}
}

func TestBatchWriterMetricsAfterOperations(t *testing.T) {
	batchSize := 3
	cfg := BatchWriterConfig{
		BatchSize:     batchSize,
		FlushInterval: time.Hour,
		MaxRetries:    0,
		RetryDelay:    time.Millisecond,
	}
	conn := &mockConn{
		prepareBatchFunc: func(_ context.Context, _ string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
			return &mockBatch{}, nil
		},
	}
	client := newMockClient(conn)
	bw := NewBatchWriter(client, cfg)
	defer bw.Close()

	// Write exactly 2 batches worth of events.
	for i := 0; i < batchSize*2; i++ {
		if err := bw.Write(newTestEvent()); err != nil {
			t.Fatalf("Write() error on event %d: %v", i, err)
		}
	}

	metrics := bw.Metrics()
	if metrics.Written != uint64(batchSize*2) {
		t.Errorf("Written = %d, want %d", metrics.Written, batchSize*2)
	}
	if metrics.Batches != 2 {
		t.Errorf("Batches = %d, want 2", metrics.Batches)
	}
	if metrics.Pending != 0 {
		t.Errorf("Pending = %d, want 0", metrics.Pending)
	}
	if metrics.Failed != 0 {
		t.Errorf("Failed = %d, want 0", metrics.Failed)
	}
}

func TestBatchWriterFlushFailureUpdatesMetrics(t *testing.T) {
	batchSize := 3
	cfg := BatchWriterConfig{
		BatchSize:     batchSize,
		FlushInterval: time.Hour,
		MaxRetries:    2,
		RetryDelay:    time.Millisecond, // keep retries fast
	}

	conn := &mockConn{
		prepareBatchFunc: func(_ context.Context, _ string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}
	client := newMockClient(conn)
	bw := NewBatchWriter(client, cfg)

	// Write enough events to trigger a flush. The flush will fail because
	// PrepareBatch always returns an error.
	for i := 0; i < batchSize; i++ {
		err := bw.Write(newTestEvent())
		if i < batchSize-1 {
			if err != nil {
				t.Fatalf("Write() #%d error = %v, want nil below batch size", i+1, err)
			}
			continue
		}
		// The last Write triggers flushLocked which will fail.
		if !errors.Is(err, ErrBatchInsertFailed) {
			t.Fatalf("Write() triggering the failing flush error = %v, want ErrBatchInsertFailed", err)
		}
	}

	// The failed batch is requeued rather than discarded. This test used to
	// expect Failed == batchSize here, i.e. the batch silently dropped (H31).
	metrics := bw.Metrics()
	if metrics.Failed != 0 {
		t.Errorf("Failed = %d, want 0 (batch requeued)", metrics.Failed)
	}
	if metrics.Pending != batchSize || metrics.Requeued != uint64(batchSize) {
		t.Errorf("Pending = %d, Requeued = %d, want %d requeued events", metrics.Pending, metrics.Requeued, batchSize)
	}
	if metrics.Written != 0 {
		t.Errorf("Written = %d, want 0 (all inserts failed)", metrics.Written)
	}
	if metrics.Batches != 0 {
		t.Errorf("Batches = %d, want 0 (no successful batches)", metrics.Batches)
	}

	// Close gives up on events that still cannot be written, and says so.
	if err := bw.Close(); !errors.Is(err, ErrBatchInsertFailed) {
		t.Fatalf("Close() error = %v, want ErrBatchInsertFailed", err)
	}
	metrics = bw.Metrics()
	if metrics.Failed != uint64(batchSize) || metrics.Pending != 0 {
		t.Errorf("after Close: Failed = %d, Pending = %d, want %d, 0", metrics.Failed, metrics.Pending, batchSize)
	}
}

// ---------------------------------------------------------------------------
// Failure handling (H30, H31)
// ---------------------------------------------------------------------------

// sinkConn is a driver.Conn whose batches record the event IDs they carry.
// sendErr decides whether a Send fails; successful sends add their IDs to
// written.
type sinkConn struct {
	mockConn

	mu        sync.Mutex
	written   []uuid.UUID
	sends     int
	sendErr   func(send int) error
	sendBlock chan struct{} // if set, Send waits for it to close
	sending   chan struct{} // if set, receives a value when Send starts
}

func (c *sinkConn) PrepareBatch(context.Context, string, ...driver.PrepareBatchOption) (driver.Batch, error) {
	return &sinkBatch{conn: c}, nil
}

func (c *sinkConn) writtenIDs() []uuid.UUID {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uuid.UUID(nil), c.written...)
}

type sinkBatch struct {
	mockBatch
	conn *sinkConn
	ids  []uuid.UUID
}

func (b *sinkBatch) Append(v ...any) error {
	b.ids = append(b.ids, v[0].(uuid.UUID))
	return nil
}

func (b *sinkBatch) Send() error {
	if b.conn.sending != nil {
		b.conn.sending <- struct{}{}
	}
	if b.conn.sendBlock != nil {
		<-b.conn.sendBlock
	}
	b.conn.mu.Lock()
	defer b.conn.mu.Unlock()
	b.conn.sends++
	if b.conn.sendErr != nil {
		if err := b.conn.sendErr(b.conn.sends); err != nil {
			return err
		}
	}
	b.conn.written = append(b.conn.written, b.ids...)
	return nil
}

// Regression (H30): flushLocked releases the mutex while inserting, and Close
// returned as soon as it saw an empty buffer, so main closed the ClickHouse
// client under a running timer flush and that batch was lost.
func TestBatchWriterCloseWaitsForInflightFlush(t *testing.T) {
	conn := &sinkConn{
		sendBlock: make(chan struct{}),
		sending:   make(chan struct{}, 1),
	}
	bw := NewBatchWriter(newMockClient(conn), BatchWriterConfig{
		BatchSize:     100,
		FlushInterval: 5 * time.Millisecond,
		RetryDelay:    time.Millisecond,
	})

	if err := bw.Write(newTestEvent()); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Wait until the timer flush is inside Send.
	select {
	case <-conn.sending:
	case <-time.After(5 * time.Second):
		t.Fatal("timer flush never started")
	}

	closed := make(chan error, 1)
	go func() { closed <- bw.Close() }()

	select {
	case err := <-closed:
		t.Fatalf("Close() returned (err=%v) while a flush was still in flight; written=%d", err, len(conn.writtenIDs()))
	case <-time.After(100 * time.Millisecond):
	}

	close(conn.sendBlock)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not return after the in-flight flush finished")
	}

	if got := len(conn.writtenIDs()); got != 1 {
		t.Errorf("written events = %d, want 1", got)
	}
	if m := bw.Metrics(); m.Written != 1 || m.Failed != 0 {
		t.Errorf("metrics = %+v, want Written 1, Failed 0", m)
	}
}

// Regression (H31): once MaxRetries were exhausted the whole batch was
// dropped, so a brief ClickHouse outage lost every batch flushed during it.
func TestBatchWriterRequeuesFailedBatch(t *testing.T) {
	var outage atomic.Bool
	outage.Store(true)
	conn := &sinkConn{sendErr: func(int) error {
		if outage.Load() {
			return errors.New("connection refused")
		}
		return nil
	}}
	bw := NewBatchWriter(newMockClient(conn), BatchWriterConfig{
		BatchSize:     3,
		FlushInterval: time.Hour,
		MaxRetries:    1,
		RetryDelay:    time.Millisecond,
	})
	defer bw.Close()

	var sent []uuid.UUID
	for i := 0; i < 3; i++ {
		ev := newTestEvent()
		sent = append(sent, ev.EventID)
		err := bw.Write(ev)
		if i == 2 && !errors.Is(err, ErrBatchInsertFailed) {
			t.Fatalf("Write() triggering the failing flush error = %v, want ErrBatchInsertFailed", err)
		}
	}

	m := bw.Metrics()
	if m.Failed != 0 || m.Pending != 3 {
		t.Fatalf("after failed flush: Failed = %d, Pending = %d, want 0 failed and 3 pending", m.Failed, m.Pending)
	}

	// ClickHouse is back: the next flush writes the requeued events.
	outage.Store(false)
	if err := bw.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if got := conn.writtenIDs(); len(got) != 3 || got[0] != sent[0] || got[2] != sent[2] {
		t.Errorf("written = %v, want %v in order", got, sent)
	}
	if m := bw.Metrics(); m.Written != 3 || m.Failed != 0 || m.Pending != 0 {
		t.Errorf("metrics = %+v, want Written 3, Failed 0, Pending 0", m)
	}
}

// Review regression: with a negative max_retries the retry loop never ran, so
// insertBatchWithRetries returned a nil error, and the requeue logic took that
// as success: every batch was discarded unwritten, with no error and no
// metric. The insert must always be attempted at least once.
func TestBatchWriterNegativeMaxRetriesStillInserts(t *testing.T) {
	var outage atomic.Bool
	conn := &sinkConn{sendErr: func(int) error {
		if outage.Load() {
			return errors.New("connection refused")
		}
		return nil
	}}
	bw := NewBatchWriter(newMockClient(conn), BatchWriterConfig{
		BatchSize:     2,
		FlushInterval: time.Hour,
		MaxRetries:    -1,
		RetryDelay:    time.Millisecond,
	})

	for i := 0; i < 2; i++ {
		if err := bw.Write(newTestEvent()); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if got := len(conn.writtenIDs()); got != 2 {
		t.Fatalf("written = %d events, want 2", got)
	}

	// A failing insert is reported and requeued, not taken for a success.
	outage.Store(true)
	for i := 0; i < 2; i++ {
		err := bw.Write(newTestEvent())
		if i == 1 && !errors.Is(err, ErrBatchInsertFailed) {
			t.Fatalf("Write() triggering the failing flush error = %v, want ErrBatchInsertFailed", err)
		}
	}
	if m := bw.Metrics(); m.Written != 2 || m.Pending != 2 || m.Requeued != 2 {
		t.Errorf("metrics = %+v, want Written 2, Pending 2, Requeued 2", m)
	}

	outage.Store(false)
	if err := bw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if m := bw.Metrics(); m.Written != 4 || m.Failed != 0 || m.Pending != 0 {
		t.Errorf("metrics after Close = %+v, want Written 4", m)
	}
}

// Requeued events go before events written while the failing insert ran.
func TestBatchWriterRequeuePreservesOrder(t *testing.T) {
	conn := &sinkConn{sendErr: func(send int) error {
		if send == 1 {
			return errors.New("boom")
		}
		return nil
	}}
	bw := NewBatchWriter(newMockClient(conn), BatchWriterConfig{BatchSize: 100, FlushInterval: time.Hour})
	defer bw.Close()

	var sent []uuid.UUID
	write := func() {
		ev := newTestEvent()
		sent = append(sent, ev.EventID)
		if err := bw.Write(ev); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	write()
	write()
	if err := bw.Flush(); !errors.Is(err, ErrBatchInsertFailed) {
		t.Fatalf("first Flush() error = %v, want ErrBatchInsertFailed", err)
	}
	write()
	if err := bw.Flush(); err != nil {
		t.Fatalf("second Flush() error = %v", err)
	}

	got := conn.writtenIDs()
	if len(got) != 3 {
		t.Fatalf("written %d events, want 3", len(got))
	}
	for i := range sent {
		if got[i] != sent[i] {
			t.Errorf("written[%d] = %v, want %v", i, got[i], sent[i])
		}
	}
}

func TestBatchWriterDeadLettersAfterMaxRequeues(t *testing.T) {
	conn := &sinkConn{sendErr: func(int) error { return errors.New("table is read-only") }}

	var mu sync.Mutex
	var dead []*schema.Event
	var causes []error
	dlq := func(_ context.Context, events []*schema.Event, cause error) error {
		mu.Lock()
		defer mu.Unlock()
		dead = append(dead, events...)
		causes = append(causes, cause)
		return nil
	}

	bw := NewBatchWriter(newMockClient(conn), BatchWriterConfig{
		BatchSize:     2,
		FlushInterval: time.Hour,
		MaxRetries:    0,
		MaxRequeues:   1,
	}, WithDeadLetter(dlq))
	defer bw.Close()

	for i := 0; i < 2; i++ {
		_ = bw.Write(newTestEvent())
	}
	// First failed flush requeues, the second exceeds MaxRequeues.
	if err := bw.Flush(); !errors.Is(err, ErrBatchInsertFailed) || !strings.Contains(err.Error(), "2 dead-lettered") {
		t.Fatalf("Flush() error = %v, want ErrBatchInsertFailed reporting 2 dead-lettered", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(dead) != 2 {
		t.Fatalf("dead-lettered %d events, want 2", len(dead))
	}
	if len(causes) != 1 || !strings.Contains(causes[0].Error(), "table is read-only") {
		t.Errorf("dead-letter causes = %v", causes)
	}
	if m := bw.Metrics(); m.Failed != 2 || m.DeadLettered != 2 || m.Pending != 0 || m.Requeued != 2 {
		t.Errorf("metrics = %+v, want Failed 2, DeadLettered 2, Pending 0, Requeued 2", m)
	}
}

func TestBatchWriterCloseReportsUnwritableEvents(t *testing.T) {
	tests := []struct {
		name      string
		dlqErr    error
		wantInErr string
		wantDead  uint64
	}{
		{name: "no dead-letter handler", wantInErr: "2 dropped"},
		{name: "dead-letter accepts", wantInErr: "2 dead-lettered", wantDead: 2},
		{name: "dead-letter fails", dlqErr: errors.New("quarantine down"), wantInErr: "2 dropped"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &sinkConn{sendErr: func(int) error { return errors.New("connection refused") }}
			var opts []BatchWriterOption
			if tt.name != "no dead-letter handler" {
				opts = append(opts, WithDeadLetter(func(context.Context, []*schema.Event, error) error { return tt.dlqErr }))
			}
			bw := NewBatchWriter(newMockClient(conn), BatchWriterConfig{BatchSize: 10, FlushInterval: time.Hour}, opts...)

			_ = bw.Write(newTestEvent())
			_ = bw.Write(newTestEvent())

			err := bw.Close()
			if !errors.Is(err, ErrBatchInsertFailed) || !strings.Contains(err.Error(), tt.wantInErr) {
				t.Fatalf("Close() error = %v, want ErrBatchInsertFailed mentioning %q", err, tt.wantInErr)
			}
			if m := bw.Metrics(); m.Failed != 2 || m.DeadLettered != tt.wantDead || m.Pending != 0 {
				t.Errorf("metrics = %+v, want Failed 2, DeadLettered %d, Pending 0", m, tt.wantDead)
			}
			if err := bw.Close(); err != nil {
				t.Errorf("second Close() error = %v, want nil", err)
			}
			if err := bw.Write(newTestEvent()); !errors.Is(err, ErrWriterClosed) {
				t.Errorf("Write() after Close error = %v, want ErrWriterClosed", err)
			}
		})
	}
}

func TestBatchWriterMaxPendingBoundsMemory(t *testing.T) {
	conn := &sinkConn{sendErr: func(int) error { return errors.New("connection refused") }}
	var dead atomic.Int64
	bw := NewBatchWriter(newMockClient(conn), BatchWriterConfig{
		BatchSize:     3,
		FlushInterval: time.Hour,
		MaxPending:    5,
		MaxRequeues:   1000,
	}, WithDeadLetter(func(_ context.Context, events []*schema.Event, _ error) error {
		dead.Add(int64(len(events)))
		return nil
	}))
	defer bw.Close()

	const total = 20
	for i := 0; i < total; i++ {
		_ = bw.Write(newTestEvent())
		if p := bw.Metrics().Pending; p > 5 {
			t.Fatalf("Pending = %d after %d writes, exceeds MaxPending 5", p, i+1)
		}
	}
	m := bw.Metrics()
	if int(m.Failed)+m.Pending != total || int64(m.Failed) != dead.Load() {
		t.Errorf("metrics = %+v, dead-lettered %d: every event must be pending or dead-lettered", m, dead.Load())
	}
}

// Every event ends up exactly once in ClickHouse or in the dead-letter
// handler, whatever the interleaving of writers, timer flushes and failures.
func TestBatchWriterConcurrentWritesWithFailuresLoseNothing(t *testing.T) {
	conn := &sinkConn{sendErr: func(send int) error {
		if send%3 != 0 {
			return errors.New("intermittent")
		}
		return nil
	}}
	var mu sync.Mutex
	var dead []uuid.UUID
	bw := NewBatchWriter(newMockClient(conn), BatchWriterConfig{
		BatchSize:     7,
		FlushInterval: time.Millisecond,
		MaxRetries:    1,
		RetryDelay:    time.Microsecond,
		MaxPending:    40,
		MaxRequeues:   2,
	}, WithDeadLetter(func(_ context.Context, events []*schema.Event, _ error) error {
		mu.Lock()
		defer mu.Unlock()
		for _, ev := range events {
			dead = append(dead, ev.EventID)
		}
		return nil
	}))

	const writers, perWriter = 8, 150
	var wg sync.WaitGroup
	var sentMu sync.Mutex
	sent := map[uuid.UUID]bool{}
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				ev := newTestEvent()
				sentMu.Lock()
				sent[ev.EventID] = true
				sentMu.Unlock()
				_ = bw.Write(ev) // errors report requeues; nothing is lost
			}
		}()
	}
	wg.Wait()
	_ = bw.Close()

	seen := map[uuid.UUID]int{}
	for _, id := range conn.writtenIDs() {
		seen[id]++
	}
	mu.Lock()
	for _, id := range dead {
		seen[id]++
	}
	mu.Unlock()

	for id := range sent {
		if seen[id] != 1 {
			t.Errorf("event %v stored %d times, want exactly once", id, seen[id])
		}
	}
	if len(seen) != len(sent) {
		t.Errorf("stored %d distinct events, sent %d", len(seen), len(sent))
	}
	m := bw.Metrics()
	if int(m.Written+m.Failed) != writers*perWriter || m.Failed != m.DeadLettered || m.Pending != 0 {
		t.Errorf("metrics = %+v, want Written+Failed = %d, all failures dead-lettered", m, writers*perWriter)
	}
}

func TestExponentialRetryBackoff(t *testing.T) {
	// The retry loop in flushLocked uses:
	//   time.Sleep(bw.config.RetryDelay * time.Duration(1<<(attempt-1)))
	// where attempt ranges from 1 to MaxRetries (attempt 0 is the initial try).
	//
	// This produces the classic exponential backoff multipliers: 1, 2, 4, 8, ...

	tests := []struct {
		attempt          int
		expectedMultiply int
	}{
		{1, 1},    // 1<<0 = 1
		{2, 2},    // 1<<1 = 2
		{3, 4},    // 1<<2 = 4
		{4, 8},    // 1<<3 = 8
		{5, 16},   // 1<<4 = 16
		{6, 32},   // 1<<5 = 32
		{10, 512}, // 1<<9 = 512
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
			multiplier := 1 << (tt.attempt - 1)
			if multiplier != tt.expectedMultiply {
				t.Errorf("1<<(%d-1) = %d, want %d", tt.attempt, multiplier, tt.expectedMultiply)
			}
		})
	}

	// Verify end-to-end delay computation with a concrete base delay.
	baseDelay := 100 * time.Millisecond
	expectedDelays := []time.Duration{
		100 * time.Millisecond,  // attempt 1: 100ms * 1
		200 * time.Millisecond,  // attempt 2: 100ms * 2
		400 * time.Millisecond,  // attempt 3: 100ms * 4
		800 * time.Millisecond,  // attempt 4: 100ms * 8
		1600 * time.Millisecond, // attempt 5: 100ms * 16
	}

	for attempt := 1; attempt <= 5; attempt++ {
		computed := baseDelay * time.Duration(1<<(attempt-1))
		if computed != expectedDelays[attempt-1] {
			t.Errorf("attempt %d: delay = %v, want %v", attempt, computed, expectedDelays[attempt-1])
		}
	}
}

func TestBatchWriterConcurrentWrite(t *testing.T) {
	cfg := BatchWriterConfig{
		BatchSize:     10000, // large to prevent flushes during test
		FlushInterval: time.Hour,
		MaxRetries:    0,
		RetryDelay:    time.Millisecond,
	}
	client := newMockClient(&mockConn{})
	bw := NewBatchWriter(client, cfg)
	defer bw.Close()

	numGoroutines := 10
	eventsPerGoroutine := 100
	totalEvents := numGoroutines * eventsPerGoroutine

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errCh := make(chan error, totalEvents)

	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				if err := bw.Write(newTestEvent()); err != nil {
					errCh <- err
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent Write() error = %v", err)
	}

	metrics := bw.Metrics()
	if metrics.Pending != totalEvents {
		t.Errorf("Pending = %d, want %d", metrics.Pending, totalEvents)
	}
}

func TestBatchWriterConcurrentWriteWithFlush(t *testing.T) {
	batchSize := 10
	cfg := BatchWriterConfig{
		BatchSize:     batchSize,
		FlushInterval: time.Hour,
		MaxRetries:    0,
		RetryDelay:    time.Millisecond,
	}

	conn := &mockConn{
		prepareBatchFunc: func(_ context.Context, _ string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
			return &mockBatch{}, nil
		},
	}
	client := newMockClient(conn)
	bw := NewBatchWriter(client, cfg)
	defer bw.Close()

	numGoroutines := 10
	eventsPerGoroutine := 50
	totalEvents := numGoroutines * eventsPerGoroutine

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				if err := bw.Write(newTestEvent()); err != nil {
					t.Errorf("Write() error = %v", err)
				}
			}
		}()
	}

	wg.Wait()

	// Every event must be accounted for: either already written or still pending.
	metrics := bw.Metrics()
	accounted := int(metrics.Written) + metrics.Pending + int(metrics.Failed)
	if accounted != totalEvents {
		t.Errorf("Written(%d) + Pending(%d) + Failed(%d) = %d, want %d",
			metrics.Written, metrics.Pending, metrics.Failed, accounted, totalEvents)
	}
}

func TestSeverityToUInt8(t *testing.T) {
	tests := []struct {
		severity int
		want     uint8
	}{
		{severity: 1, want: 1},
		{severity: 10, want: 10},
		{severity: 0, want: 0},
		{severity: 255, want: 255},
		{severity: 256, want: 255},
		{severity: 1 << 20, want: 255},
		{severity: -1, want: 0},
	}

	for _, tt := range tests {
		if got := severityToUInt8(tt.severity); got != tt.want {
			t.Errorf("severityToUInt8(%d) = %d, want %d", tt.severity, got, tt.want)
		}
	}
}
