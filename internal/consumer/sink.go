package consumer

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"boundary-siem/internal/schema"
)

// sinkDropLogInterval is the minimum gap between two WARN lines about
// events an AsyncSink had to drop.
const sinkDropLogInterval = 10 * time.Second

// sinkAbortGrace bounds how long Close waits for the forwarder after its
// context is done; the forwarder then only discards what is left.
const sinkAbortGrace = time.Second

// AsyncSink hands events to a destination that may be slower than ingestion,
// such as the correlation engine, without ever blocking the caller. Offer
// puts the event into a bounded buffer and returns at once; a single
// goroutine passes the buffered events to the process function in order.
// When the buffer is full the event is dropped for this destination only
// (storage still gets it) and counted in Metrics().Dropped.
type AsyncSink struct {
	name    string
	process func(*schema.Event)
	ch      chan *schema.Event
	done    chan struct{}

	mu     sync.RWMutex // guards closed and the close of ch against Offer
	closed bool
	abort  atomic.Bool

	offered   atomic.Uint64
	forwarded atomic.Uint64
	dropped   atomic.Uint64

	logMu      sync.Mutex
	lastLog    time.Time
	unreported uint64
}

// NewAsyncSink starts an AsyncSink named name (used in logs and metrics)
// with room for buffer events (at least 1). process is called from a single
// goroutine.
func NewAsyncSink(name string, buffer int, process func(*schema.Event)) *AsyncSink {
	if buffer < 1 {
		buffer = 1
	}
	s := &AsyncSink{
		name:    name,
		process: process,
		ch:      make(chan *schema.Event, buffer),
		done:    make(chan struct{}),
	}
	go s.forward()
	return s
}

func (s *AsyncSink) forward() {
	defer close(s.done)
	for event := range s.ch {
		if s.abort.Load() {
			s.dropped.Add(1)
			continue
		}
		s.process(event)
		s.forwarded.Add(1)
	}
}

// Offer queues event for the destination. It never blocks; it returns false
// when the event was dropped because the buffer is full or the sink is
// closed.
func (s *AsyncSink) Offer(event *schema.Event) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.closed {
		select {
		case s.ch <- event:
			s.offered.Add(1)
			return true
		default:
		}
	}
	s.dropped.Add(1)
	s.reportDrop()
	return false
}

// reportDrop logs dropped events at most once per sinkDropLogInterval.
func (s *AsyncSink) reportDrop() {
	s.logMu.Lock()
	s.unreported++
	now := time.Now()
	if !s.lastLog.IsZero() && now.Sub(s.lastLog) < sinkDropLogInterval {
		s.logMu.Unlock()
		return
	}
	n := s.unreported
	s.unreported = 0
	s.lastLog = now
	s.logMu.Unlock()

	slog.Warn("event sink is not keeping up, dropping events for it",
		"sink", s.name,
		"dropped_since_last_warning", n,
		"dropped_total", s.dropped.Load(),
		"buffer", cap(s.ch),
	)
}

// Close stops accepting events and waits until the buffered ones have been
// processed or ctx is done. In the latter case the rest of the buffer is
// discarded, counted as dropped, and an error says how many. Close is safe
// to call more than once.
func (s *AsyncSink) Close(ctx context.Context) error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
	s.mu.Unlock()

	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
	}

	before := s.dropped.Load()
	s.abort.Store(true)
	select {
	case <-s.done:
	case <-time.After(sinkAbortGrace):
	}
	discarded := s.dropped.Load() - before + uint64(len(s.ch))
	slog.Error("event sink closed before its buffer was processed",
		"sink", s.name, "discarded", discarded)
	return fmt.Errorf("sink %s: %d buffered events discarded at shutdown", s.name, discarded)
}

// Metrics returns the sink statistics.
func (s *AsyncSink) Metrics() SinkMetrics {
	return SinkMetrics{
		Offered:   s.offered.Load(),
		Forwarded: s.forwarded.Load(),
		Dropped:   s.dropped.Load(),
		Pending:   len(s.ch),
		Capacity:  cap(s.ch),
	}
}

// SinkMetrics holds AsyncSink statistics.
type SinkMetrics struct {
	// Offered counts events accepted into the buffer.
	Offered uint64 `json:"offered"`
	// Forwarded counts events passed to the destination.
	Forwarded uint64 `json:"forwarded"`
	// Dropped counts events the destination never saw (buffer full, sink
	// closed, or discarded at shutdown).
	Dropped  uint64 `json:"dropped"`
	Pending  int    `json:"pending"`
	Capacity int    `json:"capacity"`
}
