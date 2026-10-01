package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"boundary-siem/internal/storage"
)

// maxQuarantineRaw bounds the raw payload stored for one rejected event, so
// a 10 MB malformed body does not become a 10 MB quarantine row.
const maxQuarantineRaw = 64 * 1024

const (
	quarantineBatchSize     = 100
	quarantineFlushInterval = time.Second
	quarantineWriteTimeout  = 10 * time.Second
)

// QuarantineStore persists rejected events. *storage.QuarantineWriter
// implements it.
type QuarantineStore interface {
	WriteBatch(ctx context.Context, entries []*storage.QuarantineEntry) error
}

// Quarantiner stores rejected events in the background. Submit never blocks
// the request that rejected them: entries go into a bounded buffer and are
// written in batches; when the buffer is full they are dropped and counted.
// Quarantine is best effort and never changes an ingest response.
type Quarantiner struct {
	store QuarantineStore
	ch    chan *storage.QuarantineEntry
	done  chan struct{}

	baseCtx context.Context
	cancel  context.CancelFunc

	mu     sync.RWMutex
	closed bool

	submitted atomic.Uint64
	written   atomic.Uint64
	dropped   atomic.Uint64
	failed    atomic.Uint64
}

// NewQuarantiner starts a Quarantiner writing to store with room for buffer
// pending entries.
func NewQuarantiner(store QuarantineStore, buffer int) *Quarantiner {
	if buffer < 1 {
		buffer = 1000
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := &Quarantiner{
		store:   store,
		ch:      make(chan *storage.QuarantineEntry, buffer),
		done:    make(chan struct{}),
		baseCtx: ctx,
		cancel:  cancel,
	}
	go q.run()
	return q
}

// Submit queues entries for storage without blocking.
func (q *Quarantiner) Submit(entries ...*storage.QuarantineEntry) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	for _, e := range entries {
		if e == nil {
			continue
		}
		if len(e.RawEvent) > maxQuarantineRaw {
			e.RawEvent = strings.ToValidUTF8(e.RawEvent[:maxQuarantineRaw], "")
		}
		if q.closed {
			q.dropped.Add(1)
			continue
		}
		select {
		case q.ch <- e:
			q.submitted.Add(1)
		default:
			q.dropped.Add(1)
		}
	}
}

func (q *Quarantiner) run() {
	defer close(q.done)
	ticker := time.NewTicker(quarantineFlushInterval)
	defer ticker.Stop()

	batch := make([]*storage.QuarantineEntry, 0, quarantineBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(q.baseCtx, quarantineWriteTimeout)
		err := q.store.WriteBatch(ctx, batch)
		cancel()
		if err != nil {
			q.failed.Add(uint64(len(batch)))
			slog.Warn("failed to quarantine rejected events", "count", len(batch), "error", err)
		} else {
			q.written.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case e, ok := <-q.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= quarantineBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// Close stops accepting entries and writes the pending ones, giving up when
// ctx is done. It is safe to call more than once.
func (q *Quarantiner) Close(ctx context.Context) error {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.ch)
	}
	q.mu.Unlock()

	select {
	case <-q.done:
		return nil
	case <-ctx.Done():
		// Abort the write in progress; the remaining writes fail at once.
		q.cancel()
		select {
		case <-q.done:
		case <-time.After(time.Second):
		}
		return fmt.Errorf("quarantine: shutdown deadline passed with %d entries pending", len(q.ch))
	}
}

// Metrics returns quarantine statistics.
func (q *Quarantiner) Metrics() QuarantineMetrics {
	return QuarantineMetrics{
		Submitted: q.submitted.Load(),
		Written:   q.written.Load(),
		Dropped:   q.dropped.Load(),
		Failed:    q.failed.Load(),
	}
}

// QuarantineMetrics holds Quarantiner statistics.
type QuarantineMetrics struct {
	Submitted uint64 `json:"submitted"`
	Written   uint64 `json:"written"`
	// Dropped counts entries refused because the buffer was full or the
	// quarantiner was closed.
	Dropped uint64 `json:"dropped"`
	// Failed counts entries whose write to the store failed.
	Failed uint64 `json:"failed"`
}
