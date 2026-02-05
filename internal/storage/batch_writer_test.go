package storage

import (
	"context"
	"fmt"
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

func (m *mockConn) Contributors() []string                                              { return nil }
func (m *mockConn) ServerVersion() (*driver.ServerVersion, error)                       { return nil, nil }
func (m *mockConn) Select(_ context.Context, _ any, _ string, _ ...any) error           { return nil }
func (m *mockConn) Query(_ context.Context, _ string, _ ...any) (driver.Rows, error)    { return nil, nil }
func (m *mockConn) QueryRow(_ context.Context, _ string, _ ...any) driver.Row           { return nil }
func (m *mockConn) Exec(_ context.Context, _ string, _ ...any) error                    { return nil }
func (m *mockConn) AsyncInsert(_ context.Context, _ string, _ bool, _ ...any) error     { return nil }
func (m *mockConn) Ping(_ context.Context) error                                        { return nil }
func (m *mockConn) Stats() driver.Stats                                                 { return driver.Stats{} }
func (m *mockConn) Close() error                                                        { return nil }

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

func (m *mockBatch) Abort() error    { return nil }
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
	defer bw.Close()

	// Write enough events to trigger a flush. The flush will fail because
	// PrepareBatch always returns an error.
	for i := 0; i < batchSize; i++ {
		// The last Write triggers flushLocked which will fail.
		bw.Write(newTestEvent())
	}

	metrics := bw.Metrics()
	if metrics.Failed != uint64(batchSize) {
		t.Errorf("Failed = %d, want %d", metrics.Failed, batchSize)
	}
	if metrics.Written != 0 {
		t.Errorf("Written = %d, want 0 (all inserts failed)", metrics.Written)
	}
	if metrics.Batches != 0 {
		t.Errorf("Batches = %d, want 0 (no successful batches)", metrics.Batches)
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
				bw.Write(newTestEvent())
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
