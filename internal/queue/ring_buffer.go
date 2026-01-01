// Package queue provides a thread-safe ring buffer for event processing.
package queue

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"boundary-siem/internal/schema"
)

var (
	// ErrQueueFull is returned when attempting to push to a full queue.
	ErrQueueFull = errors.New("queue is full")
	// ErrQueueEmpty is returned when attempting to pop from an empty queue.
	ErrQueueEmpty = errors.New("queue is empty")
	// ErrQueueClosed is returned when attempting to use a closed queue.
	ErrQueueClosed = errors.New("queue is closed")
)

// RingBuffer is a thread-safe circular buffer for events.
type RingBuffer struct {
	buffer []*schema.Event
	size   int
	head   int
	tail   int
	count  int
	closed bool
	mu     sync.Mutex
	cond   *sync.Cond

	// Metrics (accessed atomically)
	totalPushed  uint64
	totalPopped  uint64
	totalDropped uint64
}

// NewRingBuffer creates a new RingBuffer with the specified capacity.
func NewRingBuffer(size int) *RingBuffer {
	if size <= 0 {
		size = 10000 // Default size
	}

	rb := &RingBuffer{
		buffer: make([]*schema.Event, size),
		size:   size,
	}
	rb.cond = sync.NewCond(&rb.mu)
	return rb
}

// Push adds an event to the queue.
// Returns ErrQueueFull if the queue is at capacity.
func (rb *RingBuffer) Push(event *schema.Event) error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.closed {
		return ErrQueueClosed
	}

	if rb.count == rb.size {
		atomic.AddUint64(&rb.totalDropped, 1)
		return ErrQueueFull
	}

	rb.buffer[rb.tail] = event
	rb.tail = (rb.tail + 1) % rb.size
	rb.count++
	atomic.AddUint64(&rb.totalPushed, 1)

	// Signal waiting consumers
	rb.cond.Signal()
	return nil
}

// Pop removes and returns an event from the queue.
// Returns ErrQueueEmpty if the queue is empty.
func (rb *RingBuffer) Pop() (*schema.Event, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.count == 0 {
		return nil, ErrQueueEmpty
	}

	event := rb.buffer[rb.head]
	rb.buffer[rb.head] = nil // Allow GC
	rb.head = (rb.head + 1) % rb.size
	rb.count--
	atomic.AddUint64(&rb.totalPopped, 1)

	return event, nil
}

// PopBlocking removes and returns an event from the queue.
// Blocks until an event is available or the queue is closed.
func (rb *RingBuffer) PopBlocking() (*schema.Event, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for rb.count == 0 && !rb.closed {
		rb.cond.Wait()
	}

	if rb.closed && rb.count == 0 {
		return nil, ErrQueueClosed
	}

	event := rb.buffer[rb.head]
	rb.buffer[rb.head] = nil
	rb.head = (rb.head + 1) % rb.size
	rb.count--
	atomic.AddUint64(&rb.totalPopped, 1)

	return event, nil
}

// PopWithTimeout removes and returns an event from the queue.
// Returns ErrQueueEmpty if no event is available within the timeout.
func (rb *RingBuffer) PopWithTimeout(timeout time.Duration) (*schema.Event, error) {
	deadline := time.Now().Add(timeout)

	rb.mu.Lock()
	defer rb.mu.Unlock()

	for rb.count == 0 && !rb.closed {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, ErrQueueEmpty
		}

		// Use a timer to wake up after timeout
		done := make(chan struct{})
		go func() {
			time.Sleep(remaining)
			rb.mu.Lock()
			rb.cond.Broadcast()
			rb.mu.Unlock()
			close(done)
		}()

		rb.cond.Wait()

		select {
		case <-done:
		default:
		}

		if time.Now().After(deadline) {
			return nil, ErrQueueEmpty
		}
	}

	if rb.closed && rb.count == 0 {
		return nil, ErrQueueClosed
	}

	if rb.count == 0 {
		return nil, ErrQueueEmpty
	}

	event := rb.buffer[rb.head]
	rb.buffer[rb.head] = nil
	rb.head = (rb.head + 1) % rb.size
	rb.count--
	atomic.AddUint64(&rb.totalPopped, 1)

	return event, nil
}

// Len returns the current number of events in the queue.
func (rb *RingBuffer) Len() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.count
}

// Cap returns the capacity of the queue.
func (rb *RingBuffer) Cap() int {
	return rb.size
}

// IsFull returns true if the queue is at capacity.
func (rb *RingBuffer) IsFull() bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.count == rb.size
}

// IsEmpty returns true if the queue is empty.
func (rb *RingBuffer) IsEmpty() bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.count == 0
}

// Close closes the queue and wakes up any waiting consumers.
func (rb *RingBuffer) Close() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.closed = true
	rb.cond.Broadcast()
}

// Metrics returns queue statistics.
func (rb *RingBuffer) Metrics() QueueMetrics {
	return QueueMetrics{
		Pushed:   atomic.LoadUint64(&rb.totalPushed),
		Popped:   atomic.LoadUint64(&rb.totalPopped),
		Dropped:  atomic.LoadUint64(&rb.totalDropped),
		Depth:    rb.Len(),
		Capacity: rb.size,
	}
}

// QueueMetrics holds statistics about queue operations.
type QueueMetrics struct {
	Pushed   uint64 `json:"pushed"`
	Popped   uint64 `json:"popped"`
	Dropped  uint64 `json:"dropped"`
	Depth    int    `json:"depth"`
	Capacity int    `json:"capacity"`
}
