package storage

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"boundary-siem/internal/schema"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// hogCPU keeps every P busy until stop is closed, so goroutines the driver
// starts wait in run queues the way they do while the server is ingesting a
// burst.
func hogCPU(stop <-chan struct{}) *sync.WaitGroup {
	var wg sync.WaitGroup
	for i := 0; i < 2*runtime.GOMAXPROCS(0); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x := 0
			for {
				select {
				case <-stop:
					return
				default:
				}
				for j := 0; j < 1e5; j++ {
					x += j
				}
				_ = x
			}
		}()
	}
	return &wg
}

// E2E round 1: clickhouse-go's batch.Send leaves a watchdog goroutine that
// closes the connection when the batch context is done. Cancelling the
// context right after Send returned (defer cancel()) let that watchdog close
// a connection that was already back in the pool, so concurrent inserts
// failed with "use of closed network connection" after the server had
// committed them. Every insert here must succeed on its first attempt.
func TestIntegrationConcurrentPrepareBatchKeepsPoolHealthy(t *testing.T) {
	cfg := integrationConfig(t)
	ctx := context.Background()

	client, err := NewClickHouseClient(cfg)
	if err != nil {
		t.Fatalf("NewClickHouseClient() error = %v", err)
	}
	defer client.Close()
	if err := NewMigrator(client).Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	stop := make(chan struct{})
	hogs := hogCPU(stop)
	defer func() { close(stop); hogs.Wait() }()

	const workers, perWorker = 8, 60
	var failures atomic.Int64
	var firstErr atomic.Value
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				err := func() error {
					ictx, cancel := context.WithTimeout(ctx, 30*time.Second)
					defer cancel()
					batch, err := client.PrepareBatch(ictx, "INSERT INTO events (event_id, tenant_id, timestamp, source_product, action, outcome, severity, schema_version, raw, metadata)")
					if err != nil {
						return fmt.Errorf("prepare: %w", err)
					}
					defer func() { _ = batch.Close() }()
					e := integrationEvent("pool", w*perWorker+i)
					if err := batch.Append(e.EventID, "pool", e.Timestamp, "pool-test", e.Action, string(e.Outcome), uint8(e.Severity), e.SchemaVersion, e.Raw, "{}"); err != nil {
						return fmt.Errorf("append: %w", err)
					}
					if err := batch.Send(); err != nil {
						return fmt.Errorf("send: %w", err)
					}
					return nil
				}()
				if err != nil {
					failures.Add(1)
					firstErr.CompareAndSwap(nil, err)
				}
			}
		}(w)
	}
	wg.Wait()

	if n := failures.Load(); n != 0 {
		t.Errorf("%d of %d inserts failed, first: %v", n, workers*perWorker, firstErr.Load())
	}
}

// E2E round 1: under a burst, BatchWriter must store each event exactly once
// and report exactly what it stored.
func TestIntegrationBatchWriterBurstWritesEachEventOnce(t *testing.T) {
	cfg := integrationConfig(t)
	ctx := context.Background()

	client, err := NewClickHouseClient(cfg)
	if err != nil {
		t.Fatalf("NewClickHouseClient() error = %v", err)
	}
	defer client.Close()
	if err := NewMigrator(client).Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	stop := make(chan struct{})
	hogs := hogCPU(stop)
	defer func() { close(stop); hogs.Wait() }()

	bw := NewBatchWriter(client, BatchWriterConfig{
		BatchSize: 250, FlushInterval: 50 * time.Millisecond, MaxRetries: 3, RetryDelay: 10 * time.Millisecond,
	})
	const writers, perWriter = 8, 2500
	var wg sync.WaitGroup
	var writeErrs atomic.Int64
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				e := integrationEvent("burst", i)
				e.Source.Product = "burst"
				if err := bw.Write(e); err != nil {
					writeErrs.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()
	if err := bw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	const want = writers * perWriter
	rows := integrationCount(t, client, "SELECT count() FROM events WHERE source_product = 'burst'")
	unique := integrationCount(t, client, "SELECT uniqExact(event_id) FROM events WHERE source_product = 'burst'")
	m := bw.Metrics()
	if rows != want || unique != want {
		t.Errorf("events table has %d rows / %d unique ids, want %d of each (write errors %d, metrics %+v)",
			rows, unique, want, writeErrs.Load(), m)
	}
	if m.Written != want || m.Failed != 0 {
		t.Errorf("metrics = %+v, want %d written and none failed", m, want)
	}
}

// The server drops a repeated INSERT with the same deduplication token, also
// when the repeat holds only part of the events or spans several partitions,
// and the materialized views do not see the repeat either.
func TestIntegrationInsertDeduplicationToken(t *testing.T) {
	cfg := integrationConfig(t)
	ctx := context.Background()

	client, err := NewClickHouseClient(cfg)
	if err != nil {
		t.Fatalf("NewClickHouseClient() error = %v", err)
	}
	defer client.Close()
	if err := NewMigrator(client).Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	bw := NewBatchWriter(client, BatchWriterConfig{BatchSize: 1000, FlushInterval: time.Hour})
	defer bw.Close()

	var events []*schema.Event
	for i := 0; i < 50; i++ {
		e := integrationEvent("dedup", i)
		if i%2 == 0 {
			e.Timestamp = e.Timestamp.AddDate(0, -1, 0) // a second partition
		}
		events = append(events, e)
	}
	const critical = "SELECT count() FROM events_critical WHERE tenant_id = 'dedup'"
	if err := bw.insertBatch(events, "token-a"); err != nil {
		t.Fatalf("insertBatch() error = %v", err)
	}
	wantCritical := integrationCount(t, client, critical)
	if err := bw.insertBatch(events, "token-a"); err != nil {
		t.Fatalf("repeated insertBatch() error = %v", err)
	}
	if err := bw.insertBatch(events[:10], "token-a"); err != nil {
		t.Fatalf("partial repeat insertBatch() error = %v", err)
	}
	if n := integrationCount(t, client, "SELECT count() FROM events WHERE tenant_id = 'dedup'"); n != 50 {
		t.Errorf("events after repeats under one token = %d, want 50", n)
	}
	if n := integrationCount(t, client, critical); n != wantCritical {
		t.Errorf("events_critical after repeats = %d, want %d", n, wantCritical)
	}

	more := []*schema.Event{integrationEvent("dedup", 1), integrationEvent("dedup", 2)}
	if err := bw.insertBatch(more, "token-b"); err != nil {
		t.Fatalf("insertBatch(token-b) error = %v", err)
	}
	if n := integrationCount(t, client, "SELECT count() FROM events WHERE tenant_id = 'dedup'"); n != 52 {
		t.Errorf("events after a new token = %d, want 52", n)
	}
}

// lostAckConn makes the first failSends batch sends fail after the server
// has stored them, the way a connection that drops before the reply arrives
// does.
type lostAckConn struct {
	driver.Conn
	failSends atomic.Int64
}

func (c *lostAckConn) PrepareBatch(ctx context.Context, query string, opts ...driver.PrepareBatchOption) (driver.Batch, error) {
	b, err := c.Conn.PrepareBatch(ctx, query, opts...)
	if err != nil {
		return nil, err
	}
	return &lostAckBatch{Batch: b, conn: c}, nil
}

type lostAckBatch struct {
	driver.Batch
	conn *lostAckConn
}

func (b *lostAckBatch) Send() error {
	if err := b.Batch.Send(); err != nil {
		return err
	}
	if b.conn.failSends.Add(-1) >= 0 {
		return errors.New("read: connection reset by peer (reply lost)")
	}
	return nil
}

// An insert whose reply is lost is retried, and after a requeue written
// together with newer events; neither may store an event twice.
func TestIntegrationBatchWriterLostReplyIsNotDuplicated(t *testing.T) {
	cfg := integrationConfig(t)
	ctx := context.Background()

	real, err := NewClickHouseClient(cfg)
	if err != nil {
		t.Fatalf("NewClickHouseClient() error = %v", err)
	}
	defer real.Close()
	if err := NewMigrator(real).Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	conn := &lostAckConn{Conn: real.Conn()}
	client := &ClickHouseClient{conn: conn, config: cfg}

	// MaxRetries 1: the first flush fails twice (both attempts stored) and
	// its events are requeued; the next flush adds 5 newer events.
	bw := NewBatchWriter(client, BatchWriterConfig{BatchSize: 1000, FlushInterval: time.Hour, MaxRetries: 1, RetryDelay: time.Millisecond})
	conn.failSends.Store(2)
	for i := 0; i < 20; i++ {
		if err := bw.Write(integrationEvent("lost", i)); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if err := bw.Flush(); !errors.Is(err, ErrBatchInsertFailed) {
		t.Fatalf("first Flush() error = %v, want ErrBatchInsertFailed", err)
	}
	for i := 20; i < 25; i++ {
		if err := bw.Write(integrationEvent("lost", i)); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	rows := integrationCount(t, real, "SELECT count() FROM events WHERE tenant_id = 'lost'")
	unique := integrationCount(t, real, "SELECT uniqExact(event_id) FROM events WHERE tenant_id = 'lost'")
	if rows != 25 || unique != 25 {
		t.Errorf("events table has %d rows / %d unique ids, want 25 of each", rows, unique)
	}
	if m := bw.Metrics(); m.Written != 25 || m.Failed != 0 || m.Requeued != 20 {
		t.Errorf("metrics = %+v, want 25 written, 20 requeued, none failed", m)
	}
}
