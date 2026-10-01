package consumer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
	"boundary-siem/internal/storage"
)

// slowWriter is an EventWriter that takes delay per write, like a storage
// backend under load.
type slowWriter struct {
	mockBatchWriter
	delay time.Duration
}

func (w *slowWriter) Write(event *schema.Event) error {
	time.Sleep(w.delay)
	return w.mockBatchWriter.Write(event)
}

// recordingSink counts the events it is offered.
type recordingSink struct {
	n atomic.Int64
}

func (s *recordingSink) Offer(*schema.Event) bool {
	s.n.Add(1)
	return true
}

// TestConsumer_DrainDeliversQueuedEvents is the regression test for the
// shutdown that discarded every event still in the ring buffer: the workers
// returned on cancellation without popping what was queued.
func TestConsumer_DrainDeliversQueuedEvents(t *testing.T) {
	const n = 5000
	q := queue.NewRingBuffer(n)
	for i := 0; i < n; i++ {
		if err := q.Push(newTestEvent()); err != nil {
			t.Fatalf("Push: %v", err)
		}
	}

	writer := &mockBatchWriter{}
	sink := &recordingSink{}
	c := NewConsumer(q, Config{Workers: 4, PollInterval: 5 * time.Millisecond, ShutdownWait: 10 * time.Second},
		WithWriter(writer), WithSink(sink))

	// Cancel the context right away, as the old shutdown did, and close the
	// queue for producers before draining.
	ctx, cancel := context.WithCancel(context.Background())
	c.Start(ctx)
	cancel()
	q.Close()

	if err := c.Drain(context.Background()); err != nil {
		t.Fatalf("Drain() error = %v", err)
	}
	if got := writer.written(); got != n {
		t.Errorf("stored %d events, want %d (accepted events lost at shutdown)", got, n)
	}
	if got := sink.n.Load(); got != n {
		t.Errorf("sink saw %d events, want %d", got, n)
	}
	if q.Len() != 0 {
		t.Errorf("queue still holds %d events", q.Len())
	}
	if m := c.Metrics(); m.Consumed != n || m.Errors != 0 {
		t.Errorf("metrics = %+v, want consumed=%d errors=0", m, n)
	}
}

// TestConsumer_DrainWithoutClose drains whatever is queued even when the
// queue is still open, so Stop never waits for producers.
func TestConsumer_DrainWithoutClose(t *testing.T) {
	q := queue.NewRingBuffer(100)
	writer := &mockBatchWriter{}
	c := NewConsumer(q, Config{Workers: 2, PollInterval: time.Hour, ShutdownWait: 5 * time.Second}, WithWriter(writer))
	c.Start(context.Background())

	for i := 0; i < 50; i++ {
		if err := q.Push(newTestEvent()); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	c.Stop()
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Stop took %v", elapsed)
	}
	// Workers may be parked in PopWithTimeout(time.Hour); Stop must not hang
	// on them. Every pushed event must have been delivered by then or still
	// be in the queue; none may be lost.
	if got := writer.written() + q.Len(); got != 50 {
		t.Errorf("written+queued = %d, want 50", got)
	}
}

// TestConsumer_DrainTimeout bounds the drain when storage is too slow and
// reports how many events were left behind.
func TestConsumer_DrainTimeout(t *testing.T) {
	q := queue.NewRingBuffer(1000)
	for i := 0; i < 1000; i++ {
		if err := q.Push(newTestEvent()); err != nil {
			t.Fatal(err)
		}
	}
	writer := &slowWriter{delay: 20 * time.Millisecond}
	c := NewConsumer(q, Config{Workers: 1, PollInterval: time.Millisecond, ShutdownWait: 10 * time.Second}, WithWriter(writer))
	c.Start(context.Background())
	q.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.Drain(ctx)
	if !errors.Is(err, ErrDrainTimeout) {
		t.Fatalf("Drain() error = %v, want ErrDrainTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Drain took %v, want it bounded by the context", elapsed)
	}
	if q.Len() == 0 {
		t.Error("queue unexpectedly empty; the test writer is too fast to time out")
	}
}

// failingWriter returns a flush failure on every write, like a BatchWriter
// whose ClickHouse is down: the event is kept by the writer.
type failingWriter struct {
	mockBatchWriter
}

func (w *failingWriter) Write(event *schema.Event) error {
	_ = w.mockBatchWriter.Write(event)
	return storage.NewStorageError("BatchInsert", "events", fmt.Errorf("%w: 1 events requeued", storage.ErrBatchInsertFailed))
}

func TestConsumer_FlushFailureIsNotLoss(t *testing.T) {
	q := queue.NewRingBuffer(10)
	for i := 0; i < 3; i++ {
		if err := q.Push(newTestEvent()); err != nil {
			t.Fatal(err)
		}
	}
	c := NewConsumer(q, Config{Workers: 1, PollInterval: time.Millisecond, ShutdownWait: time.Second}, WithWriter(&failingWriter{}))
	c.Start(context.Background())
	q.Close()
	if err := c.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := c.Metrics()
	if m.Consumed != 3 || m.FlushFailures != 3 || m.Errors != 0 {
		t.Errorf("metrics = %+v, want consumed=3 flush_failures=3 errors=0", m)
	}
}

func TestConsumer_ClosedWriterCountsErrors(t *testing.T) {
	q := queue.NewRingBuffer(10)
	if err := q.Push(newTestEvent()); err != nil {
		t.Fatal(err)
	}
	w := &errWriter{err: storage.ErrWriterClosed}
	c := NewConsumer(q, Config{Workers: 1, PollInterval: time.Millisecond, ShutdownWait: time.Second}, WithWriter(w))
	c.Start(context.Background())
	q.Close()
	if err := c.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := c.Metrics(); m.Errors != 1 || m.Consumed != 0 {
		t.Errorf("metrics = %+v, want errors=1 consumed=0", m)
	}
}

type errWriter struct{ err error }

func (w *errWriter) Write(*schema.Event) error { return w.err }
func (w *errWriter) Flush() error              { return nil }

// TestConsumer_NoWriter delivers to the sinks only (storage disabled).
func TestConsumer_NoWriter(t *testing.T) {
	q := queue.NewRingBuffer(10)
	sink := &recordingSink{}
	c := New(q, nil, Config{Workers: 1, PollInterval: time.Millisecond, ShutdownWait: time.Second})
	c.sinks = append(c.sinks, sink)
	c.Start(context.Background())
	for i := 0; i < 7; i++ {
		if err := q.Push(newTestEvent()); err != nil {
			t.Fatal(err)
		}
	}
	q.Close()
	if err := c.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sink.n.Load() != 7 || c.Metrics().Consumed != 7 {
		t.Errorf("sink=%d consumed=%d, want 7", sink.n.Load(), c.Metrics().Consumed)
	}
}

func TestAsyncSink_ForwardsInOrderAndDrainsOnClose(t *testing.T) {
	var mu sync.Mutex
	var got []int
	s := NewAsyncSink("test", 100, func(e *schema.Event) {
		mu.Lock()
		got = append(got, e.Severity)
		mu.Unlock()
	})
	for i := 1; i <= 50; i++ {
		ev := newTestEvent()
		ev.Severity = i
		if !s.Offer(ev) {
			t.Fatalf("Offer %d dropped", i)
		}
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 50 {
		t.Fatalf("processed %d, want 50", len(got))
	}
	for i, v := range got {
		if v != i+1 {
			t.Fatalf("out of order at %d: %v", i, got[:i+1])
		}
	}
	if s.Offer(newTestEvent()) {
		t.Error("Offer after Close accepted an event")
	}
	if m := s.Metrics(); m.Forwarded != 50 || m.Dropped != 1 {
		t.Errorf("metrics = %+v, want forwarded=50 dropped=1", m)
	}
	// Idempotent.
	if err := s.Close(context.Background()); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestAsyncSink_NeverBlocks checks that a stalled destination costs events
// for that destination only and never blocks the caller.
func TestAsyncSink_NeverBlocks(t *testing.T) {
	release := make(chan struct{})
	s := NewAsyncSink("stalled", 10, func(*schema.Event) { <-release })

	start := time.Now()
	accepted := 0
	for i := 0; i < 1000; i++ {
		if s.Offer(newTestEvent()) {
			accepted++
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("1000 offers to a stalled sink took %v", elapsed)
	}
	if accepted > 11 { // buffer plus the event being processed
		t.Errorf("accepted %d events into a 10-event buffer", accepted)
	}
	if m := s.Metrics(); m.Dropped != uint64(1000-accepted) {
		t.Errorf("dropped = %d, want %d", m.Dropped, 1000-accepted)
	}

	// Close with an expired context discards the backlog and says so.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(release)
	}()
	if err := s.Close(ctx); err == nil {
		t.Error("Close with a done context and a backlog returned nil")
	}
	if m := s.Metrics(); m.Forwarded+m.Dropped != 1000 {
		t.Errorf("forwarded %d + dropped %d != 1000 offered", m.Forwarded, m.Dropped)
	}
}
