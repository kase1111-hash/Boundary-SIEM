package consumer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
)

// mockBatchWriter is an in-memory eventWriter for testing. Consumer workers
// call it from their own goroutines, so all access is mutex-protected.
type mockBatchWriter struct {
	mu      sync.Mutex
	events  []*schema.Event
	flushes int
}

func (m *mockBatchWriter) Write(event *schema.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockBatchWriter) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushes++
	return nil
}

func (m *mockBatchWriter) written() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func (m *mockBatchWriter) flushCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushes
}

func newTestEvent() *schema.Event {
	return &schema.Event{
		EventID:   uuid.New(),
		Timestamp: time.Now().UTC(),
		Source: schema.Source{
			Product: "test",
		},
		Action:   "test.action",
		Outcome:  schema.OutcomeSuccess,
		Severity: 5,
	}
}

func TestConsumer_Metrics(t *testing.T) {
	q := queue.NewRingBuffer(100)
	cfg := DefaultConfig()

	// Create a simple consumer for metrics testing
	c := &Consumer{
		queue:  q,
		config: cfg,
		done:   make(chan struct{}),
	}

	// Test initial metrics
	m := c.Metrics()
	if m.Consumed != 0 {
		t.Errorf("Consumed = %d, want 0", m.Consumed)
	}
	if m.Errors != 0 {
		t.Errorf("Errors = %d, want 0", m.Errors)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Workers <= 0 {
		t.Error("Workers should be positive")
	}
	if cfg.PollInterval <= 0 {
		t.Error("PollInterval should be positive")
	}
	if cfg.ShutdownWait <= 0 {
		t.Error("ShutdownWait should be positive")
	}
}

func TestConsumer_StartStop(t *testing.T) {
	q := queue.NewRingBuffer(100)
	writer := &mockBatchWriter{}

	cfg := Config{
		Workers:      1,
		PollInterval: 10 * time.Millisecond,
		ShutdownWait: time.Second,
	}

	// Push some events
	const numEvents = 5
	for i := 0; i < numEvents; i++ {
		if err := q.Push(newTestEvent()); err != nil {
			t.Fatalf("Push() error = %v", err)
		}
	}

	c := &Consumer{
		queue:       q,
		batchWriter: writer,
		config:      cfg,
		done:        make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)

	// Wait for the worker to drain the queue into the writer.
	deadline := time.Now().Add(5 * time.Second)
	for c.Metrics().Consumed < numEvents {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for events: consumed %d of %d", c.Metrics().Consumed, numEvents)
		}
		time.Sleep(5 * time.Millisecond)
	}

	c.Stop()

	if got := writer.written(); got != numEvents {
		t.Errorf("writer received %d events, want %d", got, numEvents)
	}
	if got := writer.flushCount(); got != 1 {
		t.Errorf("Flush() called %d times, want 1 (final flush on Stop)", got)
	}
	m := c.Metrics()
	if m.Consumed != numEvents {
		t.Errorf("Consumed = %d, want %d", m.Consumed, numEvents)
	}
	if m.Errors != 0 {
		t.Errorf("Errors = %d, want 0", m.Errors)
	}
	if !q.IsEmpty() {
		t.Errorf("queue still holds %d events after consumer drained it", q.Len())
	}
}
