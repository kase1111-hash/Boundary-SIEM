package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

// E2E round 1: a batch insert that failed after the server had stored it was
// retried blindly, and the retry stored every event a second time. Retries
// must reuse the failed INSERT's deduplication token, also after a requeue
// that merges the failed events with newer ones.

func TestInsertGroupsKeepFailedInsertsApart(t *testing.T) {
	a1, a2 := pendingEvent{event: newTestEvent(), token: "A"}, pendingEvent{event: newTestEvent(), token: "A"}
	b1 := pendingEvent{event: newTestEvent(), token: "B"}
	n1, n2 := pendingEvent{event: newTestEvent()}, pendingEvent{event: newTestEvent()}

	groups := insertGroups([]pendingEvent{b1, a1, n1, a2, n2})
	if len(groups) != 3 {
		t.Fatalf("groups = %d, want 3 (B, A, new)", len(groups))
	}
	if groups[0].token != "B" || len(groups[0].events) != 1 {
		t.Errorf("group 0 = %q with %d events, want B with 1", groups[0].token, len(groups[0].events))
	}
	if groups[1].token != "A" || len(groups[1].events) != 2 ||
		groups[1].events[0].event != a1.event || groups[1].events[1].event != a2.event {
		t.Errorf("group 1 = %q with %d events, want A with a1, a2 in order", groups[1].token, len(groups[1].events))
	}
	if groups[2].token == "" || groups[2].token == "A" || groups[2].token == "B" || len(groups[2].events) != 2 {
		t.Errorf("group 2 = %q with %d events, want a fresh token with the 2 new events", groups[2].token, len(groups[2].events))
	}
	if again := insertGroups([]pendingEvent{n1}); again[0].token == groups[2].token {
		t.Error("new events got the same token in two flushes")
	}
}

// recordingConn records the event IDs of every INSERT attempt and fails the
// attempts for which fail returns true.
type recordingConn struct {
	mockConn
	mu       sync.Mutex
	attempts [][]uuid.UUID
	fail     func(attempt int) bool
}

func (c *recordingConn) PrepareBatch(context.Context, string, ...driver.PrepareBatchOption) (driver.Batch, error) {
	return &recordingBatch{conn: c}, nil
}

type recordingBatch struct {
	mockBatch
	conn *recordingConn
	ids  []uuid.UUID
}

func (b *recordingBatch) Append(v ...any) error {
	b.ids = append(b.ids, v[0].(uuid.UUID))
	return nil
}

func (b *recordingBatch) Send() error {
	b.conn.mu.Lock()
	defer b.conn.mu.Unlock()
	b.conn.attempts = append(b.conn.attempts, b.ids)
	if b.conn.fail != nil && b.conn.fail(len(b.conn.attempts)) {
		return errors.New("read: connection reset by peer")
	}
	return nil
}

func TestBatchWriterRequeuedEventsKeepTheirInsertToken(t *testing.T) {
	conn := &recordingConn{fail: func(attempt int) bool { return attempt <= 2 }}
	bw := NewBatchWriter(newMockClient(conn), BatchWriterConfig{
		BatchSize: 100, FlushInterval: time.Hour, MaxRetries: 1, RetryDelay: time.Millisecond,
	})

	first := []uuid.UUID{}
	for i := 0; i < 3; i++ {
		e := newTestEvent()
		first = append(first, e.EventID)
		if err := bw.Write(e); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if err := bw.Flush(); !errors.Is(err, ErrBatchInsertFailed) {
		t.Fatalf("Flush() error = %v, want ErrBatchInsertFailed", err)
	}

	bw.mu.Lock()
	var token string
	for i, p := range bw.buffer {
		if p.token == "" || (i > 0 && p.token != token) {
			t.Errorf("requeued event %d has token %q, want the failed INSERT's token %q", i, p.token, token)
		}
		token = p.token
	}
	bw.mu.Unlock()

	newer := newTestEvent()
	if err := bw.Write(newer); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Attempts 1-2: the failing INSERT and its retry, both with the same
	// three events. Then the requeued events are sent again as their own
	// INSERT (same token, so the server can drop them if attempt 1 or 2 was
	// stored), and the newer event in a separate INSERT.
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.attempts) != 4 {
		t.Fatalf("INSERT attempts = %d, want 4: %v", len(conn.attempts), conn.attempts)
	}
	for _, i := range []int{0, 1, 2} {
		if !sameIDs(conn.attempts[i], first) {
			t.Errorf("attempt %d sent %v, want exactly the first batch %v", i+1, conn.attempts[i], first)
		}
	}
	if !sameIDs(conn.attempts[3], []uuid.UUID{newer.EventID}) {
		t.Errorf("attempt 4 sent %v, want only the newer event", conn.attempts[3])
	}
	if m := bw.Metrics(); m.Written != 4 || m.Requeued != 3 || m.Failed != 0 {
		t.Errorf("metrics = %+v, want 4 written, 3 requeued", m)
	}
}

// After one INSERT of a flush has failed, the flush does not attempt the
// others: they are requeued unchanged.
func TestBatchWriterStopsFlushAfterFailedGroup(t *testing.T) {
	conn := &recordingConn{fail: func(int) bool { return true }}
	bw := NewBatchWriter(newMockClient(conn), BatchWriterConfig{
		BatchSize: 100, FlushInterval: time.Hour, MaxRetries: 0, RetryDelay: time.Millisecond,
	})
	if err := bw.Write(newTestEvent()); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := bw.Flush(); !errors.Is(err, ErrBatchInsertFailed) {
		t.Fatalf("first Flush() error = %v", err)
	}
	if err := bw.Write(newTestEvent()); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := bw.Flush(); !errors.Is(err, ErrBatchInsertFailed) {
		t.Fatalf("second Flush() error = %v", err)
	}
	conn.mu.Lock()
	attempts := len(conn.attempts)
	conn.mu.Unlock()
	if attempts != 2 {
		t.Errorf("INSERT attempts = %d, want 2 (the second flush stops after its first failed INSERT)", attempts)
	}
	bw.mu.Lock()
	if len(bw.buffer) != 2 || bw.buffer[1].token != "" {
		t.Errorf("buffer after failed flushes = %+v, want 2 events, the unattempted one without a token", bw.buffer)
	}
	bw.mu.Unlock()
	_ = bw.Close()
}

// E2E round 1: during a ClickHouse outage siem_storage_pending read 0 while
// thousands of events sat in a flush that kept retrying.
func TestBatchWriterPendingIncludesInflightFlush(t *testing.T) {
	conn := &sinkConn{sendBlock: make(chan struct{}), sending: make(chan struct{}, 1)}
	bw := NewBatchWriter(newMockClient(conn), BatchWriterConfig{BatchSize: 3, FlushInterval: time.Hour, RetryDelay: time.Millisecond})

	done := make(chan error, 1)
	go func() {
		for i := 0; i < 3; i++ {
			if err := bw.Write(newTestEvent()); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case <-conn.sending:
	case <-time.After(5 * time.Second):
		t.Fatal("flush never reached Send")
	}
	if m := bw.Metrics(); m.Pending != 3 {
		t.Errorf("Pending during the flush = %d, want 3 (the in-flight events)", m.Pending)
	}
	close(conn.sendBlock)
	if err := <-done; err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if m := bw.Metrics(); m.Pending != 0 || m.Written != 3 {
		t.Errorf("after the flush: %+v, want Pending 0, Written 3", m)
	}
	_ = bw.Close()
}

func sameIDs(a, b []uuid.UUID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// E2E round 1: PrepareBatch must detach the batch from the caller's context
// once the batch is sent, so that the caller's deferred cancel cannot reach
// clickhouse-go's Send watchdog after the connection is back in the pool.
func TestPrepareBatchDetachesContextAfterSend(t *testing.T) {
	var batchCtx context.Context
	conn := &mockConn{prepareBatchFunc: func(ctx context.Context, _ string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
		batchCtx = ctx
		return &mockBatch{}, nil
	}}
	client := newMockClient(conn)

	type key struct{}
	parent, cancel := context.WithTimeout(context.WithValue(context.Background(), key{}, "v"), time.Hour)
	batch, err := client.PrepareBatch(parent, "INSERT INTO events")
	if err != nil {
		t.Fatalf("PrepareBatch() error = %v", err)
	}
	want, _ := parent.Deadline()
	if got, ok := batchCtx.Deadline(); !ok || !got.Equal(want) {
		t.Errorf("batch context deadline = %v, %v, want %v (the driver applies it to the connection)", got, ok, want)
	}
	if batchCtx.Value(key{}) != "v" {
		t.Error("batch context lost the caller's values (query settings)")
	}

	if err := batch.Send(); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	cancel()
	select {
	case <-batchCtx.Done():
		t.Fatal("cancelling the caller's context after Send cancelled the batch context")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestPrepareBatchFollowsCallerCancellationUntilSent(t *testing.T) {
	var batchCtx context.Context
	conn := &mockConn{prepareBatchFunc: func(ctx context.Context, _ string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
		batchCtx = ctx
		return &mockBatch{sendFunc: func() error {
			<-batchCtx.Done() // a Send that only ends when interrupted
			return batchCtx.Err()
		}}, nil
	}}
	parent, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	batch, err := newMockClient(conn).PrepareBatch(parent, "INSERT INTO events")
	if err != nil {
		t.Fatalf("PrepareBatch() error = %v", err)
	}
	err = batch.Send()
	if !errors.Is(err, context.Canceled) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Send() error = %v, want the cancellation with its cause (deadline exceeded)", err)
	}
}
