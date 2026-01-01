package queue

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/schema"
)

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

func TestNewRingBuffer(t *testing.T) {
	t.Run("with valid size", func(t *testing.T) {
		rb := NewRingBuffer(100)
		if rb.Cap() != 100 {
			t.Errorf("Cap() = %d, want 100", rb.Cap())
		}
		if rb.Len() != 0 {
			t.Errorf("Len() = %d, want 0", rb.Len())
		}
	})

	t.Run("with zero size uses default", func(t *testing.T) {
		rb := NewRingBuffer(0)
		if rb.Cap() != 10000 {
			t.Errorf("Cap() = %d, want 10000 (default)", rb.Cap())
		}
	})

	t.Run("with negative size uses default", func(t *testing.T) {
		rb := NewRingBuffer(-5)
		if rb.Cap() != 10000 {
			t.Errorf("Cap() = %d, want 10000 (default)", rb.Cap())
		}
	})
}

func TestRingBuffer_PushPop(t *testing.T) {
	rb := NewRingBuffer(10)

	t.Run("push single event", func(t *testing.T) {
		event := newTestEvent()
		if err := rb.Push(event); err != nil {
			t.Errorf("Push() error = %v", err)
		}
		if rb.Len() != 1 {
			t.Errorf("Len() = %d, want 1", rb.Len())
		}
	})

	t.Run("pop single event", func(t *testing.T) {
		event, err := rb.Pop()
		if err != nil {
			t.Errorf("Pop() error = %v", err)
		}
		if event == nil {
			t.Error("Pop() returned nil event")
		}
		if rb.Len() != 0 {
			t.Errorf("Len() = %d, want 0", rb.Len())
		}
	})

	t.Run("pop from empty queue", func(t *testing.T) {
		_, err := rb.Pop()
		if err != ErrQueueEmpty {
			t.Errorf("Pop() error = %v, want ErrQueueEmpty", err)
		}
	})
}

func TestRingBuffer_FIFO(t *testing.T) {
	rb := NewRingBuffer(10)

	// Push 5 events with distinct IDs
	ids := make([]uuid.UUID, 5)
	for i := 0; i < 5; i++ {
		event := newTestEvent()
		ids[i] = event.EventID
		if err := rb.Push(event); err != nil {
			t.Fatalf("Push() error = %v", err)
		}
	}

	// Pop and verify order
	for i := 0; i < 5; i++ {
		event, err := rb.Pop()
		if err != nil {
			t.Fatalf("Pop() error = %v", err)
		}
		if event.EventID != ids[i] {
			t.Errorf("Pop() returned event with ID %v, want %v", event.EventID, ids[i])
		}
	}
}

func TestRingBuffer_Full(t *testing.T) {
	rb := NewRingBuffer(3)

	// Fill the queue
	for i := 0; i < 3; i++ {
		if err := rb.Push(newTestEvent()); err != nil {
			t.Fatalf("Push() error = %v", err)
		}
	}

	if !rb.IsFull() {
		t.Error("IsFull() = false, want true")
	}

	// Try to push to full queue
	if err := rb.Push(newTestEvent()); err != ErrQueueFull {
		t.Errorf("Push() error = %v, want ErrQueueFull", err)
	}

	// Verify metrics
	metrics := rb.Metrics()
	if metrics.Dropped != 1 {
		t.Errorf("Metrics().Dropped = %d, want 1", metrics.Dropped)
	}
}

func TestRingBuffer_Wrap(t *testing.T) {
	rb := NewRingBuffer(3)

	// Push 3, pop 2
	for i := 0; i < 3; i++ {
		rb.Push(newTestEvent())
	}
	rb.Pop()
	rb.Pop()

	// Push 2 more (should wrap around)
	for i := 0; i < 2; i++ {
		if err := rb.Push(newTestEvent()); err != nil {
			t.Errorf("Push() error = %v after wrap", err)
		}
	}

	if rb.Len() != 3 {
		t.Errorf("Len() = %d, want 3", rb.Len())
	}
}

func TestRingBuffer_IsEmpty(t *testing.T) {
	rb := NewRingBuffer(10)

	if !rb.IsEmpty() {
		t.Error("IsEmpty() = false for new buffer")
	}

	rb.Push(newTestEvent())
	if rb.IsEmpty() {
		t.Error("IsEmpty() = true after Push")
	}

	rb.Pop()
	if !rb.IsEmpty() {
		t.Error("IsEmpty() = false after Pop")
	}
}

func TestRingBuffer_Metrics(t *testing.T) {
	rb := NewRingBuffer(5)

	// Initial metrics
	m := rb.Metrics()
	if m.Pushed != 0 || m.Popped != 0 || m.Dropped != 0 {
		t.Errorf("Initial metrics = %+v, want all zeros", m)
	}

	// Push 3 events
	for i := 0; i < 3; i++ {
		rb.Push(newTestEvent())
	}

	m = rb.Metrics()
	if m.Pushed != 3 {
		t.Errorf("Pushed = %d, want 3", m.Pushed)
	}
	if m.Depth != 3 {
		t.Errorf("Depth = %d, want 3", m.Depth)
	}

	// Pop 2 events
	rb.Pop()
	rb.Pop()

	m = rb.Metrics()
	if m.Popped != 2 {
		t.Errorf("Popped = %d, want 2", m.Popped)
	}
	if m.Depth != 1 {
		t.Errorf("Depth = %d, want 1", m.Depth)
	}
}

func TestRingBuffer_Close(t *testing.T) {
	rb := NewRingBuffer(10)
	rb.Push(newTestEvent())

	rb.Close()

	// Push to closed queue should fail
	if err := rb.Push(newTestEvent()); err != ErrQueueClosed {
		t.Errorf("Push() error = %v, want ErrQueueClosed", err)
	}

	// Pop remaining events should still work
	event, err := rb.Pop()
	if err != nil {
		t.Errorf("Pop() error = %v", err)
	}
	if event == nil {
		t.Error("Pop() returned nil")
	}

	// Pop from empty closed queue
	_, err = rb.PopBlocking()
	if err != ErrQueueClosed {
		t.Errorf("PopBlocking() error = %v, want ErrQueueClosed", err)
	}
}

func TestRingBuffer_PopBlocking(t *testing.T) {
	rb := NewRingBuffer(10)

	// Start a goroutine that will push an event after a delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		rb.Push(newTestEvent())
	}()

	// PopBlocking should wait and return the event
	start := time.Now()
	event, err := rb.PopBlocking()
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("PopBlocking() error = %v", err)
	}
	if event == nil {
		t.Error("PopBlocking() returned nil")
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("PopBlocking() returned too quickly: %v", elapsed)
	}
}

func TestRingBuffer_PopWithTimeout(t *testing.T) {
	rb := NewRingBuffer(10)

	t.Run("timeout on empty queue", func(t *testing.T) {
		start := time.Now()
		_, err := rb.PopWithTimeout(50 * time.Millisecond)
		elapsed := time.Since(start)

		if err != ErrQueueEmpty {
			t.Errorf("PopWithTimeout() error = %v, want ErrQueueEmpty", err)
		}
		if elapsed < 40*time.Millisecond {
			t.Errorf("PopWithTimeout() returned too quickly: %v", elapsed)
		}
	})

	t.Run("returns event if available", func(t *testing.T) {
		rb.Push(newTestEvent())

		event, err := rb.PopWithTimeout(100 * time.Millisecond)
		if err != nil {
			t.Errorf("PopWithTimeout() error = %v", err)
		}
		if event == nil {
			t.Error("PopWithTimeout() returned nil")
		}
	})
}

func TestRingBuffer_Concurrent(t *testing.T) {
	rb := NewRingBuffer(100)

	const numProducers = 5
	const numConsumers = 3
	const eventsPerProducer = 100

	var wg sync.WaitGroup
	var produced, consumed uint64

	// Start producers
	for i := 0; i < numProducers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < eventsPerProducer; j++ {
				// Push and count if successful - drops are expected when queue is full
				if err := rb.Push(newTestEvent()); err == nil {
					atomic.AddUint64(&produced, 1)
				}
			}
		}()
	}

	// Start consumers
	done := make(chan struct{})
	for i := 0; i < numConsumers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					// Drain remaining
					for {
						if _, err := rb.Pop(); err != nil {
							return
						}
						atomic.AddUint64(&consumed, 1)
					}
				default:
					if _, err := rb.Pop(); err == nil {
						atomic.AddUint64(&consumed, 1)
					} else {
						time.Sleep(time.Microsecond)
					}
				}
			}
		}()
	}

	// Wait for producers to finish
	time.Sleep(200 * time.Millisecond)
	close(done)

	// Wait for all goroutines
	wg.Wait()

	// Verify no data loss
	metrics := rb.Metrics()
	totalExpected := uint64(numProducers * eventsPerProducer)

	if metrics.Pushed+metrics.Dropped != totalExpected {
		t.Errorf("Pushed(%d) + Dropped(%d) = %d, want %d",
			metrics.Pushed, metrics.Dropped, metrics.Pushed+metrics.Dropped, totalExpected)
	}
}
