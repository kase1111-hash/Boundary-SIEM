package app

import (
	"context"
	"errors"
	"math"
	"time"
)

// ShutdownReport summarises a shutdown, in particular whether every event
// accepted into the queue reached storage.
type ShutdownReport struct {
	Duration time.Duration

	// Accepted is every event accepted into the queue (HTTP, CEF, EVM).
	Accepted uint64
	// Undrained events were still in the queue when the drain gave up.
	Undrained int
	// StoreTimedOut is set when the final storage flush did not finish in
	// time; StorePending events were still buffered then.
	StoreTimedOut bool
	StorePending  int
	// StoreDropped events were given up on by the batch writer and not
	// dead-lettered; ConsumerErrors events were refused by it.
	StoreDropped   uint64
	ConsumerErrors uint64
	// CorrelationDropped events never reached the correlation engine.
	CorrelationDropped uint64

	// Lost is the number of accepted events that are not in storage (when
	// storage is enabled).
	Lost uint64

	// AlertsUnpersisted is the number of alerts whose latest change was
	// still not in storage after the final alert flush (their write failed
	// and was queued); AlertWritesDropped counts failed alert writes never
	// queued because too many were pending. Those changes are lost; the
	// alert manager logs them at ERROR.
	AlertsUnpersisted  int
	AlertWritesDropped uint64
}

// Shutdown stops the service within timeout, in an order that loses no
// accepted event while storage is healthy:
//
//  1. stop the listeners (HTTP, WebSocket, CEF, EVM), so nothing new arrives;
//  2. close the queue and drain it through the consumer into storage and
//     the correlation engine;
//  3. flush and close the batch writer and the quarantine writer;
//  4. let the correlation engine finish, then stop it and alerting (alerts
//     raised meanwhile are still persisted unless storage hangs past the
//     deadline, in which case their handling is aborted and the aborted
//     writes are queued like any other failed alert write);
//  5. make one final attempt to write the alert changes whose write failed
//     (see alerting.Manager.Close);
//  6. close the ClickHouse connection.
//
// Every phase is bounded by its share of timeout. Events and alert changes
// that cannot be stored in time are counted in the report and logged at
// ERROR. Shutdown is safe to call more than once; later calls return the
// first report.
func (a *App) Shutdown(timeout time.Duration) ShutdownReport {
	a.shutdownOnce.Do(func() { a.report = a.shutdown(timeout) })
	return a.report
}

func (a *App) shutdown(timeout time.Duration) ShutdownReport {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	// Leave room for the final alert flush and the bounded ClickHouse close
	// after the last phase.
	if a.alertMgr.Persistent() && timeout > 2*alertFlushGrace {
		timeout -= alertFlushGrace
	}
	if a.chClient != nil && timeout > 2*storageCloseGrace {
		timeout -= storageCloseGrace
	}
	start := time.Now()
	deadline := start.Add(timeout)
	until := func(t time.Time) (context.Context, context.CancelFunc) {
		if t.After(deadline) {
			t = deadline
		}
		return context.WithDeadline(context.Background(), t)
	}
	frac := func(f float64) time.Duration { return time.Duration(float64(timeout) * f) }
	log := a.logger

	a.handler.SetShuttingDown()

	// 1. Stop intake. In-flight HTTP requests finish (their events are in
	// the queue before Shutdown returns).
	httpCtx, cancel := until(start.Add(frac(0.25)))
	if err := a.server.Shutdown(httpCtx); err != nil {
		log.Warn("HTTP server did not stop in time, closing connections", "error", err)
		_ = a.server.Close()
	}
	cancel()
	if a.hub != nil {
		a.hub.Close()
	}
	if a.evm != nil {
		a.evm.Stop()
	}
	if a.udp != nil {
		a.udp.Stop()
	}
	if a.tcp != nil {
		a.tcp.Stop()
	}
	if a.dtls != nil {
		a.dtls.Stop()
	}

	// 2. Drain the queue. Leave 30% of the budget for flushing storage and
	// finishing correlation.
	a.queue.Close()
	drainCtx, cancel := until(deadline.Add(-frac(0.30)))
	drainErr := a.consumer.Drain(drainCtx)
	cancel()

	report := ShutdownReport{Undrained: a.queue.Len()}

	// 3. Flush storage.
	if a.store != nil {
		storeCtx, cancel := until(deadline.Add(-frac(0.10)))
		if err := runWithin(storeCtx, a.store.Close); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				report.StoreTimedOut = true
				log.Error("storage flush did not finish before the shutdown deadline",
					"unwritten_events", a.unsettledEvents())
			} else {
				log.Error("batch writer close error", "error", err)
			}
		}
		cancel()
	}
	if a.quarantine != nil {
		qCtx, cancel := until(deadline.Add(-frac(0.05)))
		if err := a.quarantine.Close(qCtx); err != nil {
			log.Warn("quarantine writer close", "error", err)
		}
		cancel()
	}

	// 4. Correlation: hand over what the consumer queued for the engine,
	// let the engine work through it, then stop it and alerting. The last
	// 5% of the budget is kept for stopping and closing storage.
	corrCtx, cancel := until(deadline.Add(-frac(0.05)))
	if err := a.corrSink.Close(corrCtx); err != nil {
		log.Warn("correlation input not fully processed", "error", err)
	}
	waitEngineIdle(corrCtx, a.engine.Stats)
	cancel()
	stopCtx, cancel := until(deadline)
	a.stopAlerting(stopCtx)
	cancel()

	a.cancelRun()
	a.bg.Wait()
	a.stopRateLimiter()

	// 5. Alert changes whose write failed are kept in memory and retried in
	// the background; make one last attempt to write them, within what is
	// left of the budget plus alertFlushGrace. The alert manager logs at
	// ERROR what it could not write.
	flushBy := deadline
	if now := time.Now(); now.After(flushBy) {
		flushBy = now
	}
	flushCtx, cancel := context.WithDeadline(context.Background(), flushBy.Add(alertFlushGrace))
	report.AlertsUnpersisted = a.alertMgr.Close(flushCtx)
	cancel()
	report.AlertWritesDropped = a.alertMgr.PersistenceMetrics().DroppedWrites

	// 6. Close storage. database/sql waits for running queries, which a
	// frozen server never finishes, so this is bounded too.
	if a.chClient != nil {
		closeCtx, cancel := context.WithTimeout(context.Background(), storageCloseGrace)
		if err := runWithin(closeCtx, a.chClient.Close); err != nil {
			log.Error("clickhouse close error", "error", err)
		}
		cancel()
	}

	report.Duration = time.Since(start)
	report.Accepted = a.queue.Metrics().Pushed
	cm := a.consumer.Metrics()
	report.ConsumerErrors = cm.Errors
	report.CorrelationDropped = a.corrSink.Metrics().Dropped
	if a.store != nil {
		bm := a.store.Metrics()
		report.StoreDropped = bm.Failed - bm.DeadLettered
		if report.StoreTimedOut {
			report.StorePending = a.unsettledEvents()
		}
		// Every accepted event is in the events table, in events_quarantine
		// or lost: still queued, inside a storage write that never returned
		// (which the counters above cannot see), in a flush that did not
		// finish, or refused or dropped by the writer.
		if stored := bm.Written + bm.DeadLettered; report.Accepted > stored {
			report.Lost = report.Accepted - stored
		}
	}
	a.logReport(report, drainErr)
	return report
}

// stopAbortGrace bounds how long stopAlerting waits for the correlation
// engine and escalation to return once their context has been cancelled.
const stopAbortGrace = 500 * time.Millisecond

// stopAlerting stops the correlation engine and the escalation engine. Both
// wait for their alert handlers, which persist alerts to ClickHouse with the
// run context: against a frozen server such a call only returns when that
// context is cancelled (or after the driver's 5 minute read timeout). So when
// ctx is done first, the run context is cancelled to abort them, and
// stopAlerting waits at most stopAbortGrace more.
func (a *App) stopAlerting(ctx context.Context) {
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		a.engine.Stop()
		a.escalation.Stop()
	}()
	select {
	case <-stopped:
		return
	case <-ctx.Done():
	}
	a.logger.Error("correlation engine and alerting did not stop before the shutdown deadline; aborting in-flight alert handling (aborted alert writes are left to the final alert flush)")
	a.cancelRun()
	select {
	case <-stopped:
	case <-time.After(stopAbortGrace):
		a.logger.Error("correlation engine and alerting still running after abort")
	}
}

// unsettledEvents returns the events handed to the storage writer that it
// has neither written nor given up on: still buffered, or in a flush that has
// not finished.
func (a *App) unsettledEvents() int {
	consumed := a.consumer.Metrics().Consumed
	bm := a.store.Metrics()
	settled := bm.Written + bm.Failed
	if consumed <= settled {
		return 0
	}
	return int(min(consumed-settled, uint64(math.MaxInt32)))
}

// storageCloseGrace bounds closing the ClickHouse connection pool.
const storageCloseGrace = 500 * time.Millisecond

// alertFlushGrace is the time the final alert flush gets beyond the
// shutdown phases (reserved from the budget when it is large enough).
const alertFlushGrace = time.Second

// runWithin runs fn and waits for it until ctx is done. fn keeps running in
// the background after a timeout; the process is about to exit.
func runWithin(ctx context.Context, fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// waitEngineIdle waits until the correlation engine's event and alert
// channels are empty or ctx is done.
func waitEngineIdle(ctx context.Context, stats func() map[string]interface{}) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		s := stats()
		events, _ := s["event_queue"].(int)
		alerts, _ := s["alert_queue"].(int)
		if events == 0 && alerts == 0 {
			// One more tick so a worker can finish the event it popped
			// last and hand its alert to the dispatcher.
			select {
			case <-ctx.Done():
			case <-ticker.C:
			}
			s = stats()
			events, _ = s["event_queue"].(int)
			alerts, _ = s["alert_queue"].(int)
			if events == 0 && alerts == 0 {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *App) logReport(r ShutdownReport, drainErr error) {
	log := a.logger
	qm := a.queue.Metrics()
	log.Info("queue metrics",
		"events_pushed", qm.Pushed,
		"events_popped", qm.Popped,
		"events_rejected_queue_full", qm.Dropped,
		"events_left_in_queue", qm.Depth,
	)
	if a.store != nil {
		bm := a.store.Metrics()
		log.Info("storage metrics",
			"events_written", bm.Written,
			"events_failed", bm.Failed,
			"events_dead_lettered", bm.DeadLettered,
			"events_requeued", bm.Requeued,
			"batches", bm.Batches,
		)
	}
	sm := a.corrSink.Metrics()
	log.Info("correlation metrics",
		"events_forwarded", sm.Forwarded,
		"events_dropped", sm.Dropped,
		"rules", len(a.engine.GetRules()),
	)
	for _, s := range a.sources() {
		log.Info("CEF metrics",
			"transport", s.Transport,
			"received", s.Received,
			"queued", s.Queued,
			"errors", s.Errors,
			"parse_errors", s.ParseErrors,
			"validation_errors", s.ValidationErrors,
			"oversized_lines", s.OversizedLines,
		)
	}
	if a.hub != nil {
		hm := a.hub.Metrics()
		log.Info("websocket metrics",
			"connections", hm.Connections,
			"auth_failures", hm.AuthFailures,
			"slow_clients_dropped", hm.SlowClientsDropped,
			"messages_sent", hm.MessagesSent,
		)
	}

	attrs := []any{
		"duration_ms", r.Duration.Milliseconds(),
		"events_accepted", r.Accepted,
		"events_lost", r.Lost,
		"events_undrained", r.Undrained,
		"storage_timed_out", r.StoreTimedOut,
		"correlation_dropped", r.CorrelationDropped,
	}
	if a.alertMgr.Persistent() {
		attrs = append(attrs, "alerts_unpersisted", r.AlertsUnpersisted, "alert_writes_dropped", r.AlertWritesDropped)
	}
	if drainErr != nil {
		attrs = append(attrs, "drain_error", drainErr.Error())
	}
	switch {
	case r.Lost > 0:
		log.Error("shutdown complete with lost events", attrs...)
	case r.AlertsUnpersisted > 0 || r.AlertWritesDropped > 0:
		log.Error("shutdown complete with alert changes not persisted", attrs...)
	default:
		log.Info("shutdown complete", attrs...)
	}
}
