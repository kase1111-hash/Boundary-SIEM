package alerting

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Alert writes that fail.
//
// The in-memory alerts are the source of truth. Every change (a new alert, a
// merged recurrence, a lifecycle action, an escalation note) is applied in
// memory first and then written to the database as the alert's complete
// new row (see persistAlert). When that write fails, typically because
// ClickHouse is unreachable, the change stays applied and the alert is
// marked pending. The background writer (Start) writes the latest version
// of every pending alert once storage answers again, with exponential
// backoff between attempts while it does not, and Close makes one final
// bounded attempt and logs at ERROR the alerts it could not write.
//
// Writing an alert's full current row is idempotent: the alerts table is a
// ReplacingMergeTree(updated_at) sorted by (tenant_id, created_at, alert_id)
// (see migration 004 and storage.fixAlertsSortingKey), and every read
// selects the version with the greatest updated_at. Retries may therefore
// repeat a version or race with a newer one without changing what is read.
//
// Without this, a failed write was logged and forgotten: an alert raised
// during an outage never reached the database and was lost on restart.

// pendingWrite records an alert whose latest change is not in the database.
type pendingWrite struct {
	// version is the updated_at of the newest version whose write failed.
	// A successful write of that version or a later one clears the entry.
	version time.Time
	// since is when the first unpersisted change failed to be written.
	since time.Time
	// lastAttempt is the last failed write; retries take the least recently
	// attempted alerts first, so one alert that keeps failing cannot hold up
	// the others.
	lastAttempt time.Time
	// failures counts the failed writes.
	failures int
}

// writeState is the background writer of a Manager and its counters.
type writeState struct {
	wake chan struct{} // signalled when an alert becomes pending

	failed, retried, dropped atomic.Uint64

	mu     sync.Mutex // guards cancel and done
	cancel context.CancelFunc
	done   chan struct{} // closed when the background writer has returned
}

// PersistenceMetrics reports how alert changes reach the database.
type PersistenceMetrics struct {
	// PendingWrites is the number of alerts whose latest change is not yet in
	// the database: its write failed and is retried in the background.
	PendingWrites int `json:"pending_writes"`
	// FailedWrites counts failed alert writes, first attempts and retries.
	FailedWrites uint64 `json:"failed_writes"`
	// RetriedWrites counts alert versions written by a retry after an
	// earlier write of the alert had failed.
	RetriedWrites uint64 `json:"retried_writes"`
	// DroppedWrites counts failed writes that were not queued for retry
	// because MaxPendingWrites alerts were already pending. Those changes
	// are in memory only (unless a later change of the same alert is
	// written) and are lost on restart.
	DroppedWrites uint64 `json:"dropped_writes"`
}

// Persistent reports whether the manager writes alerts to a database.
func (m *Manager) Persistent() bool {
	return m.db != nil
}

// PersistenceMetrics returns the alert persistence counters.
func (m *Manager) PersistenceMetrics() PersistenceMetrics {
	m.mu.RLock()
	pending := len(m.pending)
	m.mu.RUnlock()
	return PersistenceMetrics{
		PendingWrites: pending,
		FailedWrites:  m.writes.failed.Load(),
		RetriedWrites: m.writes.retried.Load(),
		DroppedWrites: m.writes.dropped.Load(),
	}
}

// store writes snapshot, the new version of an alert, to the database, if
// there is one. When the write fails the change stays applied in memory and
// the alert is queued for the background writer; change names the change
// for the log.
func (m *Manager) store(ctx context.Context, snapshot *Alert, change string) {
	if m.db == nil {
		return
	}
	err := m.writeAlert(ctx, snapshot)
	if err == nil {
		m.markPersisted(snapshot.ID, snapshot.UpdatedAt)
		return
	}
	m.writes.failed.Add(1)
	pending, queued := m.markPending(snapshot)
	if !queued {
		slog.Error("alert change not persisted and not queued for retry: too many alert writes are pending; it is kept in memory only and lost on restart",
			"alert_id", snapshot.ID, "rule_id", snapshot.RuleID, "severity", snapshot.Severity, "change", change,
			"max_pending_writes", m.config.MaxPendingWrites, "error", err)
		return
	}
	slog.Warn("failed to persist alert change; it is applied in memory and queued for retry",
		"alert_id", snapshot.ID, "rule_id", snapshot.RuleID, "severity", snapshot.Severity, "change", change,
		"pending_writes", pending, "error", err)
}

// writeAlert writes one version of an alert, bounded by PersistTimeout.
func (m *Manager) writeAlert(ctx context.Context, alert *Alert) error {
	ctx, cancel := context.WithTimeout(ctx, m.config.PersistTimeout)
	defer cancel()
	return m.persistAlert(ctx, alert)
}

// markPending records that the write of snapshot failed. It returns the
// number of pending alerts, and false when the alert was not queued because
// MaxPendingWrites alerts are already pending.
func (m *Manager) markPending(snapshot *Alert) (int, bool) {
	now := time.Now()
	m.mu.Lock()
	if p, ok := m.pending[snapshot.ID]; ok {
		if snapshot.UpdatedAt.After(p.version) {
			p.version = snapshot.UpdatedAt
		}
		p.lastAttempt = now
		p.failures++
		n := len(m.pending)
		m.mu.Unlock()
		return n, true
	}
	if len(m.pending) >= m.config.MaxPendingWrites {
		m.mu.Unlock()
		m.writes.dropped.Add(1)
		return 0, false
	}
	if _, ok := m.alerts[snapshot.ID]; !ok {
		// Cleanup removed the alert after the change was made. Memory must
		// keep it until it is written.
		m.alerts[snapshot.ID] = snapshot.clone()
	}
	m.pending[snapshot.ID] = &pendingWrite{version: snapshot.UpdatedAt, since: now, lastAttempt: now, failures: 1}
	n := len(m.pending)
	m.mu.Unlock()

	select {
	case m.writes.wake <- struct{}{}:
	default:
	}
	return n, true
}

// markPersisted records that version of an alert was written: the alert is
// no longer pending unless a later version failed to be written.
func (m *Manager) markPersisted(id uuid.UUID, version time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.pending[id]; ok && !p.version.After(version) {
		delete(m.pending, id)
	}
}

// markRetryFailed records a failed retry of a pending alert.
func (m *Manager) markRetryFailed(id uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.pending[id]; ok {
		p.lastAttempt = time.Now()
		p.failures++
	}
}

// pendingIDs returns the pending alerts, least recently attempted first.
func (m *Manager) pendingIDs() []uuid.UUID {
	type entry struct {
		id   uuid.UUID
		last time.Time
	}
	m.mu.RLock()
	entries := make([]entry, 0, len(m.pending))
	for id, p := range m.pending {
		entries = append(entries, entry{id: id, last: p.lastAttempt})
	}
	m.mu.RUnlock()

	slices.SortFunc(entries, func(a, b entry) int {
		if c := a.last.Compare(b.last); c != 0 {
			return c
		}
		return bytes.Compare(a.id[:], b.id[:])
	})
	ids := make([]uuid.UUID, len(entries))
	for i, e := range entries {
		ids[i] = e.id
	}
	return ids
}

// writePending writes the latest version of every pending alert, least
// recently attempted first. With stopOnFailure it stops at the first failed
// write (storage is presumably still down); otherwise it tries every alert
// until ctx is done. It returns the number of alerts written and the first
// error.
func (m *Manager) writePending(ctx context.Context, stopOnFailure bool) (written int, err error) {
	for _, id := range m.pendingIDs() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			if err == nil {
				err = ctxErr
			}
			return written, err
		}
		m.mu.RLock()
		_, stillPending := m.pending[id]
		alert, inMemory := m.alerts[id]
		var snapshot *Alert
		if stillPending && inMemory {
			snapshot = alert.clone()
		}
		m.mu.RUnlock()
		if snapshot == nil {
			// Written by a newer change meanwhile, or (which Cleanup and
			// markPending prevent) no longer in memory.
			continue
		}

		if werr := m.writeAlert(ctx, snapshot); werr != nil {
			m.writes.failed.Add(1)
			m.markRetryFailed(id)
			if err == nil {
				err = werr
			}
			if stopOnFailure {
				return written, err
			}
			continue
		}
		m.markPersisted(id, snapshot.UpdatedAt)
		m.writes.retried.Add(1)
		written++
	}
	return written, err
}

// Start starts the background writer that retries failed alert writes
// until ctx is done or Close is called. It waits PersistRetryInitial after
// a write fails, then doubles the wait after each failed attempt up to
// PersistRetryMax; each attempt stops at its first failed write, so an
// outage costs one write per attempt. It does nothing without a database or
// when already started.
func (m *Manager) Start(ctx context.Context) {
	if m.db == nil {
		return
	}
	m.writes.mu.Lock()
	defer m.writes.mu.Unlock()
	if m.writes.done != nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	m.writes.cancel = cancel
	m.writes.done = make(chan struct{})
	go m.retryLoop(ctx, m.writes.done)
}

func (m *Manager) retryLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	backoff := m.config.PersistRetryInitial
	timer := time.NewTimer(backoff)
	timer.Stop() // armed before each attempt
	defer timer.Stop()
	failing := false
	for {
		if m.PersistenceMetrics().PendingWrites == 0 {
			backoff = m.config.PersistRetryInitial
			select {
			case <-ctx.Done():
				return
			case <-m.writes.wake:
			}
			continue
		}

		timer.Reset(backoff)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		written, err := m.writePending(ctx, true)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			failing = true
			backoff = min(backoff*2, m.config.PersistRetryMax)
			slog.Warn("alert storage unavailable; queued alert changes will be retried",
				"pending_writes", m.PersistenceMetrics().PendingWrites, "written", written,
				"retry_in", backoff.String(), "error", err)
			continue
		}
		if written > 0 {
			slog.Info("wrote alert changes queued after storage failures", "count", written, "after_failed_attempts", failing)
		}
		failing = false
		backoff = m.config.PersistRetryInitial
	}
}

// maxLoggedAlertIDs bounds the alert IDs listed in the shutdown log.
const maxLoggedAlertIDs = 20

// Close stops the background writer and makes one final attempt, bounded
// by ctx, to write every pending alert. The alerts still not written are
// logged at ERROR, with the number of writes dropped because too many were
// pending, so that no loss goes unnoticed. It returns the number of alerts
// whose latest change is not in the database. Without a database it does
// nothing and returns 0.
func (m *Manager) Close(ctx context.Context) int {
	m.writes.mu.Lock()
	cancel, done := m.writes.cancel, m.writes.done
	m.writes.mu.Unlock()
	if cancel != nil {
		cancel()
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
	if m.db == nil {
		return 0
	}

	var (
		written int
		err     error
	)
	if m.PersistenceMetrics().PendingWrites > 0 {
		written, err = m.writePending(ctx, false)
	}
	left := m.pendingIDs()
	dropped := m.writes.dropped.Load()
	switch {
	case len(left) > 0:
		logged := left[:min(len(left), maxLoggedAlertIDs)]
		ids := make([]string, len(logged))
		for i, id := range logged {
			ids[i] = id.String()
		}
		attrs := []any{"unpersisted_alerts", len(left), "alert_ids", ids, "written_at_shutdown", written, "dropped_writes", dropped}
		if err != nil {
			attrs = append(attrs, "error", err)
		}
		slog.Error("alert changes not persisted at shutdown; they are lost on restart", attrs...)
	case dropped > 0:
		slog.Error("alert changes were dropped while storage was unavailable and are not persisted",
			"dropped_writes", dropped, "written_at_shutdown", written)
	case written > 0:
		slog.Info("wrote queued alert changes at shutdown", "count", written)
	}
	return len(left)
}
