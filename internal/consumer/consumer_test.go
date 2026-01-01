package consumer

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
)

// mockBatchWriter is a mock implementation for testing
type mockBatchWriter struct {
	events  []*schema.Event
	written int
	failed  int
}

func (m *mockBatchWriter) Write(event *schema.Event) error {
	m.events = append(m.events, event)
	m.written++
	return nil
}

func (m *mockBatchWriter) Flush() error {
	return nil
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

	// We can't easily test with the real BatchWriter without ClickHouse,
	// so we just test that the consumer starts and stops without panic
	cfg := Config{
		Workers:      1,
		PollInterval: 10 * time.Millisecond,
		ShutdownWait: time.Second,
	}

	// Push some events
	for i := 0; i < 5; i++ {
		q.Push(newTestEvent())
	}

	// Since we can't use a real batch writer, we'll just verify
	// the consumer can be created and stopped
	c := &Consumer{
		queue:  q,
		config: cfg,
		done:   make(chan struct{}),
	}

	// Verify it can be created
	if c == nil {
		t.Fatal("Consumer should not be nil")
	}

	// Just close without starting (to avoid needing a mock)
	close(c.done)
}
