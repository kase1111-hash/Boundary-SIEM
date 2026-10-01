package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"boundary-siem/internal/ingest"
)

const (
	storageCheckInterval = 5 * time.Second
	storagePingTimeout   = 2 * time.Second
)

// storageHealth tracks storage reachability with a periodic ping, so /health
// and /ready (which are unauthenticated) never hit ClickHouse themselves.
type storageHealth struct {
	ping func(context.Context) error // nil: nothing to check

	// inflight is set while a ping runs. A ping that ignores its context
	// (a frozen server can hold a pooled connection) must not stall the
	// checker or pile up goroutines.
	inflight atomic.Bool

	mu        sync.RWMutex
	status    string
	message   string
	checkedAt time.Time
}

func newStorageHealth(ping func(context.Context) error) *storageHealth {
	return &storageHealth{ping: ping, status: ingest.StatusUp}
}

// errPingTimeout reports a ping that did not answer within storagePingTimeout.
var errPingTimeout = errors.New("no answer within " + storagePingTimeout.String())

// pingOnce runs the ping with storagePingTimeout and waits at most that long
// for it, whatever the driver does with the context.
func (s *storageHealth) pingOnce(ctx context.Context) error {
	if !s.inflight.CompareAndSwap(false, true) {
		return errors.New("previous ping still pending")
	}
	result := make(chan error, 1)
	pingCtx, cancel := context.WithTimeout(ctx, storagePingTimeout)
	go func() {
		defer s.inflight.Store(false)
		defer cancel()
		result <- s.ping(pingCtx)
	}()
	timer := time.NewTimer(storagePingTimeout + 100*time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-timer.C:
		return errPingTimeout
	case <-ctx.Done():
		return ctx.Err()
	}
}

// check pings storage once. flushFailuresDelta is the number of failed
// flushes since the previous check; any marks storage as degraded even when
// the ping succeeds.
func (s *storageHealth) check(ctx context.Context, flushFailuresDelta uint64) {
	if s.ping == nil {
		return
	}
	err := s.pingOnce(ctx)
	if ctx.Err() != nil {
		return // shutting down
	}

	// /health is unauthenticated: the message names the problem but not the
	// error text (which can carry internal addresses); that goes to the log.
	status, message := ingest.StatusUp, ""
	switch {
	case errors.Is(err, errPingTimeout):
		status, message = ingest.StatusDown, "ping timed out"
	case err != nil:
		status, message = ingest.StatusDown, "ping failed"
	case flushFailuresDelta > 0:
		status, message = ingest.StatusDegraded, fmt.Sprintf("%d failed flushes in the last %s", flushFailuresDelta, storageCheckInterval)
	}

	s.mu.Lock()
	previous := s.status
	s.status, s.message, s.checkedAt = status, message, time.Now()
	s.mu.Unlock()

	switch status {
	case previous:
	case ingest.StatusUp:
		slog.Info("storage health recovered", "previous", previous)
	default:
		slog.Warn("storage health changed", "status", status, "message", message, "error", err)
	}
}

// run checks storage every storageCheckInterval until ctx is done.
func (s *storageHealth) run(ctx context.Context, flushFailures func() uint64) {
	if s.ping == nil {
		return
	}
	last := flushFailures()
	s.check(ctx, 0)
	ticker := time.NewTicker(storageCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := flushFailures()
			s.check(ctx, now-last)
			last = now
		}
	}
}

func (s *storageHealth) get() (string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status, s.message
}

// components reports subsystem status for /health and /ready.
func (a *App) components() map[string]ingest.ComponentStatus {
	cfg := a.cfg
	out := make(map[string]ingest.ComponentStatus, 8)

	if a.store == nil {
		out["storage"] = ingest.ComponentStatus{Status: ingest.StatusDisabled}
	} else {
		status, message := a.storage.get()
		out["storage"] = ingest.ComponentStatus{Status: status, Enabled: true, Message: message}
	}

	transport := func(enabled bool, address string) ingest.ComponentStatus {
		if !enabled {
			return ingest.ComponentStatus{Status: ingest.StatusDisabled}
		}
		return ingest.ComponentStatus{Status: ingest.StatusUp, Enabled: true, Address: address}
	}
	out["cef_udp"] = transport(a.udp != nil, cfg.Ingest.CEF.UDP.Address)
	out["cef_tcp"] = transport(a.tcp != nil, cfg.Ingest.CEF.TCP.Address)
	dtls := transport(a.dtls != nil, cfg.Ingest.CEF.DTLS.Address)
	if a.dtls != nil && !a.dtls.IsSecure() && a.started.Load() {
		dtls.Status = ingest.StatusDegraded
		dtls.Message = "running as plain UDP (allow_insecure)"
	}
	out["cef_dtls"] = dtls
	out["evm"] = transport(a.evm != nil, "")

	corr := a.corrSink.Metrics()
	correlation := ingest.ComponentStatus{
		Status:  ingest.StatusUp,
		Enabled: true,
		Message: fmt.Sprintf("%d rules", len(a.engine.GetRules())),
	}
	if corr.Capacity > 0 && corr.Pending*10 >= corr.Capacity*9 {
		correlation.Status = ingest.StatusDegraded
		correlation.Message += fmt.Sprintf(", input buffer %d/%d full", corr.Pending, corr.Capacity)
	}
	out["correlation"] = correlation

	if a.hub != nil {
		out["websocket"] = ingest.ComponentStatus{
			Status:  ingest.StatusUp,
			Enabled: true,
			Message: fmt.Sprintf("%d clients", a.hub.Clients()),
		}
	} else {
		out["websocket"] = ingest.ComponentStatus{Status: ingest.StatusDisabled}
	}
	return out
}

// sources reports the CEF transport counters for /metrics.
func (a *App) sources() []ingest.SourceMetrics {
	var out []ingest.SourceMetrics
	if a.udp != nil {
		m := a.udp.Metrics()
		out = append(out, ingest.SourceMetrics{Transport: "udp", Received: m.Received, Queued: m.Queued,
			Errors: m.Errors, ParseErrors: m.ParseErrors, ValidationErrors: m.ValidationErrors})
	}
	if a.tcp != nil {
		m := a.tcp.Metrics()
		out = append(out, ingest.SourceMetrics{Transport: "tcp", Received: m.Received, Queued: m.Queued,
			Errors: m.Errors, ParseErrors: m.ParseErrors, ValidationErrors: m.ValidationErrors, OversizedLines: m.OversizedLines})
	}
	if a.dtls != nil {
		m := a.dtls.Metrics()
		out = append(out, ingest.SourceMetrics{Transport: "dtls", Received: m.Received, Queued: m.Queued,
			Errors: m.Errors, ParseErrors: m.ParseErrors, ValidationErrors: m.ValidationErrors})
	}
	return out
}

// metrics reports pipeline counters for /metrics.
func (a *App) metrics() []ingest.Metric {
	counter := func(name, help string, v uint64) ingest.Metric {
		return ingest.Metric{Name: name, Help: help, Type: "counter", Value: float64(v)}
	}
	gauge := func(name, help string, v float64) ingest.Metric {
		return ingest.Metric{Name: name, Help: help, Type: "gauge", Value: v}
	}

	cm := a.consumer.Metrics()
	sm := a.corrSink.Metrics()
	out := []ingest.Metric{
		counter("siem_consumer_events_total", "Events delivered by the queue consumer", cm.Consumed),
		counter("siem_consumer_errors_total", "Events the storage writer refused (lost)", cm.Errors),
		counter("siem_consumer_flush_failures_total", "Writes whose storage flush failed (events kept for retry)", cm.FlushFailures),
		counter("siem_correlation_events_total", "Events passed to the correlation engine", sm.Forwarded),
		counter("siem_correlation_events_dropped_total", "Events the correlation engine never saw because its input buffer was full", sm.Dropped),
		gauge("siem_correlation_buffer_depth", "Events waiting for the correlation engine", float64(sm.Pending)),
		gauge("siem_correlation_rules", "Correlation rules loaded", float64(len(a.engine.GetRules()))),
	}

	if stats := a.alertMgr.Stats(); stats != nil {
		if total, ok := stats["total"].(int); ok {
			out = append(out, gauge("siem_alerts", "Alerts held by the alert manager", float64(total)))
		}
	}

	if a.store != nil {
		bm := a.store.Metrics()
		out = append(out,
			counter("siem_storage_events_written_total", "Events written to the events table", bm.Written),
			counter("siem_storage_events_failed_total", "Events not written to the events table (includes dead-lettered)", bm.Failed),
			counter("siem_storage_events_dead_lettered_total", "Events moved to events_quarantine after failed inserts", bm.DeadLettered),
			counter("siem_storage_events_requeued_total", "Events put back after a failed flush", bm.Requeued),
			gauge("siem_storage_pending", "Events buffered for the next storage flush", float64(bm.Pending)),
		)
		status, _ := a.storage.get()
		up := 0.0
		if status != ingest.StatusDown {
			up = 1
		}
		out = append(out, gauge("siem_storage_up", "1 when storage answered the last health check", up))
	}

	if a.hub != nil {
		hm := a.hub.Metrics()
		out = append(out,
			gauge("siem_websocket_clients", "Authenticated WebSocket clients", float64(hm.Clients)),
			counter("siem_websocket_connections_total", "WebSocket connections accepted", hm.Connections),
			counter("siem_websocket_auth_failures_total", "WebSocket connections closed with 4401", hm.AuthFailures),
			counter("siem_websocket_slow_clients_dropped_total", "WebSocket clients disconnected for not keeping up", hm.SlowClientsDropped),
		)
	}

	components := a.components()
	names := []string{"storage", "cef_udp", "cef_tcp", "cef_dtls", "evm", "correlation", "websocket"}
	for _, name := range names {
		c, ok := components[name]
		if !ok || !c.Enabled {
			continue
		}
		up := 0.0
		if c.Status == ingest.StatusUp || c.Status == ingest.StatusDegraded {
			up = 1
		}
		out = append(out, ingest.Metric{
			Name: "siem_component_up", Help: "1 when an enabled component is up or degraded, 0 when down",
			Type: "gauge", Labels: map[string]string{"component": name}, Value: up,
		})
	}
	return out
}
