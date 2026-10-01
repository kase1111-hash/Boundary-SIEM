// Package alerting provides alert management and notification capabilities.
package alerting

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"sync"
	"time"

	"boundary-siem/internal/correlation"

	"github.com/google/uuid"
)

// AlertStatus represents the status of an alert.
type AlertStatus string

const (
	StatusNew          AlertStatus = "new"
	StatusAcknowledged AlertStatus = "acknowledged"
	StatusInProgress   AlertStatus = "in_progress"
	StatusResolved     AlertStatus = "resolved"
	StatusSuppressed   AlertStatus = "suppressed"
)

var (
	// ErrAlertNotFound is returned when no alert has the requested ID.
	ErrAlertNotFound = errors.New("alert not found")
	// ErrInvalidTransition is returned when a lifecycle action is not valid
	// for the alert's current status (for example acknowledging a resolved
	// alert).
	ErrInvalidTransition = errors.New("invalid alert status transition")
)

// Alert represents a managed alert.
type Alert struct {
	ID          uuid.UUID                 `json:"id"`
	RuleID      string                    `json:"rule_id"`
	RuleName    string                    `json:"rule_name"`
	Severity    correlation.Severity      `json:"severity"`
	Status      AlertStatus               `json:"status"`
	Title       string                    `json:"title"`
	Description string                    `json:"description"`
	CreatedAt   time.Time                 `json:"created_at"`
	UpdatedAt   time.Time                 `json:"updated_at"`
	AckedAt     *time.Time                `json:"acked_at,omitempty"`
	AckedBy     string                    `json:"acked_by,omitempty"`
	ResolvedAt  *time.Time                `json:"resolved_at,omitempty"`
	ResolvedBy  string                    `json:"resolved_by,omitempty"`
	GroupKey    string                    `json:"group_key,omitempty"`
	EventCount  int                       `json:"event_count"`
	EventIDs    []uuid.UUID               `json:"event_ids,omitempty"`
	Tags        []string                  `json:"tags,omitempty"`
	MITRE       *correlation.MITREMapping `json:"mitre,omitempty"`
	Metadata    map[string]interface{}    `json:"metadata,omitempty"`
	Notes       []Note                    `json:"notes,omitempty"`
	AssignedTo  string                    `json:"assigned_to,omitempty"`
}

// clone returns a copy of the alert that shares no mutable state with it.
// Metadata is copied one level deep; nested values are never mutated by the
// manager.
func (a *Alert) clone() *Alert {
	c := *a
	if a.AckedAt != nil {
		t := *a.AckedAt
		c.AckedAt = &t
	}
	if a.ResolvedAt != nil {
		t := *a.ResolvedAt
		c.ResolvedAt = &t
	}
	c.EventIDs = slices.Clone(a.EventIDs)
	c.Tags = slices.Clone(a.Tags)
	c.Notes = slices.Clone(a.Notes)
	if a.MITRE != nil {
		mitre := *a.MITRE
		mitre.Techniques = slices.Clone(a.MITRE.Techniques)
		c.MITRE = &mitre
	}
	c.Metadata = maps.Clone(a.Metadata)
	return &c
}

// Note represents a note on an alert.
type Note struct {
	ID        uuid.UUID `json:"id"`
	Author    string    `json:"author"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

// NotificationChannel defines a notification channel interface.
type NotificationChannel interface {
	Name() string
	Send(ctx context.Context, alert *Alert) error
}

// ManagerConfig configures the alert manager.
type ManagerConfig struct {
	DeduplicationWindow time.Duration
	RetentionPeriod     time.Duration
	MaxAlerts           int

	// MaxPendingWrites bounds the alerts whose latest change could not be
	// written to the database and waits for a retry (see Manager.Start).
	// A failed write beyond it is not queued: it is logged at ERROR and
	// counted in PersistenceMetrics.DroppedWrites. Zero means
	// DefaultMaxPendingWrites.
	MaxPendingWrites int
	// PersistRetryInitial and PersistRetryMax bound the exponential backoff
	// between retries of pending writes while storage stays unavailable.
	// Zero means DefaultPersistRetryInitial and DefaultPersistRetryMax.
	PersistRetryInitial time.Duration
	PersistRetryMax     time.Duration
	// PersistTimeout bounds each alert write. Zero means
	// DefaultPersistTimeout.
	PersistTimeout time.Duration
}

// Defaults of the persistence settings of ManagerConfig.
const (
	DefaultMaxPendingWrites    = 10000
	DefaultPersistRetryInitial = time.Second
	DefaultPersistRetryMax     = 30 * time.Second
	DefaultPersistTimeout      = 10 * time.Second
)

// DefaultManagerConfig returns default manager configuration.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		DeduplicationWindow: 15 * time.Minute,
		RetentionPeriod:     30 * 24 * time.Hour, // 30 days
		MaxAlerts:           100000,
		MaxPendingWrites:    DefaultMaxPendingWrites,
		PersistRetryInitial: DefaultPersistRetryInitial,
		PersistRetryMax:     DefaultPersistRetryMax,
		PersistTimeout:      DefaultPersistTimeout,
	}
}

// withDefaults fills in the persistence settings left at zero.
func (c ManagerConfig) withDefaults() ManagerConfig {
	if c.MaxPendingWrites <= 0 {
		c.MaxPendingWrites = DefaultMaxPendingWrites
	}
	if c.PersistRetryInitial <= 0 {
		c.PersistRetryInitial = DefaultPersistRetryInitial
	}
	if c.PersistRetryMax <= 0 {
		c.PersistRetryMax = DefaultPersistRetryMax
	}
	c.PersistRetryMax = max(c.PersistRetryMax, c.PersistRetryInitial)
	if c.PersistTimeout <= 0 {
		c.PersistTimeout = DefaultPersistTimeout
	}
	return c
}

// Manager manages alerts and notifications.
//
// Alerts are held in memory, which is the source of truth, and, when db is
// non-nil, persisted to the ClickHouse "alerts" table (see persistence.go).
// A change whose write fails stays applied in memory and its alert is
// queued: the background writer started by Start writes the alert's latest
// version once storage is back, and Close makes a final attempt (see
// pending.go). Every accessor returns a snapshot (deep copy) of an alert, so
// callers may read or encode it without holding the manager's lock while
// lifecycle methods mutate the original.
type Manager struct {
	config      ManagerConfig
	db          *sql.DB
	channels    []NotificationChannel
	recurrences []func(*Alert)              // OnRecurrence listeners
	alerts      map[uuid.UUID]*Alert        // guarded by mu
	dedup       map[string]dedupEntry       // "rule_id:group_key" -> latest alert; guarded by mu
	pending     map[uuid.UUID]*pendingWrite // alerts whose latest change is not stored; guarded by mu
	mu          sync.RWMutex

	writes writeState // background writer and persistence counters
}

// dedupEntry is the latest alert raised for a rule and group, and when that
// alert was last raised or recurred.
type dedupEntry struct {
	alertID uuid.UUID
	last    time.Time
}

// maxAlertEventIDs bounds the event IDs an alert keeps in memory as
// recurrences are merged into it; EventCount keeps the full count.
const maxAlertEventIDs = 1000

// NewManager creates a new alert manager. db is the database/sql handle of
// the ClickHouse store (storage.ClickHouseClient.DB()); pass nil to keep
// alerts in memory only.
func NewManager(config ManagerConfig, db *sql.DB) *Manager {
	return &Manager{
		config:   config.withDefaults(),
		db:       db,
		channels: make([]NotificationChannel, 0),
		alerts:   make(map[uuid.UUID]*Alert),
		dedup:    make(map[string]dedupEntry),
		pending:  make(map[uuid.UUID]*pendingWrite),
		writes:   writeState{wake: make(chan struct{}, 1)},
	}
}

// AddChannel adds a notification channel.
func (m *Manager) AddChannel(channel NotificationChannel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.channels = append(m.channels, channel)
	slog.Info("added notification channel", "name", channel.Name())
}

// OnRecurrence registers fn to be called with a snapshot of an open alert
// each time a recurrence is merged into it (its event count, event IDs,
// metadata and updated_at changed). Merged recurrences are not sent to the
// notification channels, which only see new alerts, so this is how live
// views learn about them. fn runs on the goroutine that handles the
// correlation alert, after the change has been stored or queued; it must
// not block and must not modify the alert, which all listeners share.
func (m *Manager) OnRecurrence(fn func(alert *Alert)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recurrences = append(m.recurrences, fn)
}

// HandleCorrelationAlert handles an alert from the correlation engine.
//
// Deduplication: when the rule fired for the same group within
// DeduplicationWindow of the previous occurrence and that alert is still
// open (any status but resolved), the recurrence is merged into it: its
// event count, event IDs and updated_at grow, metadata.occurrences counts
// the merged alerts, and no notification is sent. Once the alert has been
// resolved, a recurrence raises a new alert: the attack resumed. (Every
// recurrence within a fixed window from the first alert used to be dropped,
// logged at debug only, even after the alert was resolved.)
//
// The correlation engine sends the firings of a rule and group within its
// own dedup window as recurrences (correlation.Alert.Recurrence) instead of
// dropping them, each listing only events no earlier alert reported; they
// are handled here like any other alert.
func (m *Manager) HandleCorrelationAlert(ctx context.Context, corrAlert *correlation.Alert) error {
	dedupKey := dedupKeyOf(corrAlert.RuleID, corrAlert.GroupKey)
	now := time.Now()
	alert := newManagedAlert(corrAlert)

	m.mu.Lock()
	if entry, ok := m.dedup[dedupKey]; ok && now.Sub(entry.last) < m.config.DeduplicationWindow {
		if open, ok := m.alerts[entry.alertID]; ok && open.Status != StatusResolved {
			m.dedup[dedupKey] = dedupEntry{alertID: open.ID, last: now}
			mergeRecurrence(open, corrAlert, nextUpdateTime(open.UpdatedAt))
			snapshot := open.clone()
			m.mu.Unlock()

			slog.Info("alert recurred; merged into the open alert",
				"rule_id", corrAlert.RuleID, "group_key", corrAlert.GroupKey,
				"alert_id", snapshot.ID, "status", snapshot.Status,
				"occurrences", snapshot.Metadata[metaOccurrences], "event_count", snapshot.EventCount)
			m.store(ctx, snapshot, "merge recurrence")
			m.notifyRecurrence(snapshot)
			return nil
		}
	}
	// The alert is stored under the same lock as its dedup entry: a
	// concurrent recurrence that found the entry but not yet the alert used
	// to raise (and notify) a second alert.
	m.dedup[dedupKey] = dedupEntry{alertID: alert.ID, last: now}
	m.alerts[alert.ID] = alert
	snapshot := alert.clone()
	m.mu.Unlock()

	m.store(ctx, snapshot, "create")
	m.sendNotifications(ctx, snapshot)
	return nil
}

// notifyRecurrence calls the OnRecurrence listeners with a snapshot of an
// alert a recurrence was merged into.
func (m *Manager) notifyRecurrence(alert *Alert) {
	m.mu.RLock()
	listeners := m.recurrences
	m.mu.RUnlock()
	for _, fn := range listeners {
		fn(alert)
	}
}

// newManagedAlert converts an alert of the correlation engine into a new
// managed alert.
func newManagedAlert(corrAlert *correlation.Alert) *Alert {
	eventIDs := make([]uuid.UUID, len(corrAlert.Events))
	for i, e := range corrAlert.Events {
		eventIDs[i] = e.EventID
	}

	createdAt := corrAlert.Timestamp
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	var mitre *correlation.MITREMapping
	if corrAlert.MITRE != nil {
		mitreCopy := *corrAlert.MITRE
		mitreCopy.Techniques = slices.Clone(corrAlert.MITRE.Techniques)
		mitre = &mitreCopy
	}

	return &Alert{
		ID:          corrAlert.ID,
		RuleID:      corrAlert.RuleID,
		RuleName:    corrAlert.RuleName,
		Severity:    correlation.IntToSeverity(corrAlert.Severity),
		Status:      StatusNew,
		Title:       corrAlert.Title,
		Description: corrAlert.Description,
		CreatedAt:   createdAt,
		UpdatedAt:   createdAt,
		GroupKey:    corrAlert.GroupKey,
		EventCount:  len(corrAlert.Events),
		EventIDs:    eventIDs,
		Tags:        slices.Clone(corrAlert.Tags),
		MITRE:       mitre,
		Metadata:    make(map[string]interface{}),
	}
}

// Metadata keys maintained on alerts that recurrences were merged into.
const (
	metaOccurrences    = "occurrences"
	metaLastOccurrence = "last_occurrence"
)

// dedupKeyOf is the deduplication key of a rule and group.
func dedupKeyOf(ruleID, groupKey string) string {
	return fmt.Sprintf("%s:%s", ruleID, groupKey)
}

// mergeRecurrence folds a recurrence of alert's rule and group into alert.
// The caller holds the manager lock.
//
// Events the alert already lists are not counted again. The correlation
// engine reports every event once (see correlation.EngineConfig); this
// guards against a recurrence that repeats events anyway, as far as the
// alert's (bounded) event ID list can tell.
func mergeRecurrence(alert *Alert, recurrence *correlation.Alert, now time.Time) {
	known := make(map[uuid.UUID]struct{}, len(alert.EventIDs))
	for _, id := range alert.EventIDs {
		known[id] = struct{}{}
	}
	for _, e := range recurrence.Events {
		if _, dup := known[e.EventID]; dup {
			continue
		}
		known[e.EventID] = struct{}{}
		alert.EventCount++
		if len(alert.EventIDs) < maxAlertEventIDs {
			alert.EventIDs = append(alert.EventIDs, e.EventID)
		}
	}
	if alert.Metadata == nil {
		alert.Metadata = make(map[string]interface{})
	}
	occurrences := 1
	switch n := alert.Metadata[metaOccurrences].(type) {
	case int:
		occurrences = n
	case float64: // decoded from the persisted JSON
		occurrences = int(n)
	}
	alert.Metadata[metaOccurrences] = occurrences + 1
	seen := recurrence.Timestamp
	if seen.IsZero() {
		seen = now
	}
	alert.Metadata[metaLastOccurrence] = seen.UTC().Format(time.RFC3339Nano)
	alert.UpdatedAt = now
}

// sendNotifications sends an alert snapshot to all channels. Channels only
// read the alert, so one snapshot is shared between them.
func (m *Manager) sendNotifications(ctx context.Context, alert *Alert) {
	m.mu.RLock()
	channels := m.channels
	m.mu.RUnlock()

	for _, channel := range channels {
		go func(ch NotificationChannel) {
			if err := ch.Send(ctx, alert); err != nil {
				slog.Error("notification failed",
					"channel", ch.Name(),
					"alert_id", alert.ID,
					"error", err)
			} else {
				slog.Debug("notification sent",
					"channel", ch.Name(),
					"alert_id", alert.ID)
			}
		}(channel)
	}
}

// GetAlert retrieves a snapshot of an alert by ID. Alerts that are not in
// memory are looked up in the database, if one is configured.
func (m *Manager) GetAlert(ctx context.Context, id uuid.UUID) (*Alert, error) {
	m.mu.RLock()
	if alert, ok := m.alerts[id]; ok {
		snapshot := alert.clone()
		m.mu.RUnlock()
		return snapshot, nil
	}
	m.mu.RUnlock()

	// Try database
	if m.db != nil {
		return m.loadAlert(ctx, id)
	}
	return nil, fmt.Errorf("%w: %s", ErrAlertNotFound, id)
}

// ListAlerts lists snapshots of alerts with optional filters, newest first.
// Falls back to database if in-memory store has no results and DB is available.
func (m *Manager) ListAlerts(ctx context.Context, filter AlertFilter) ([]*Alert, error) {
	results, matched := m.listInMemory(filter)

	// Fall back to database if in-memory store is empty and DB is available
	if matched == 0 && m.db != nil {
		dbResults, err := m.listAlertsFromDB(ctx, filter)
		if err != nil {
			slog.Warn("failed to list alerts from database, returning in-memory results", "error", err)
		} else {
			sortAlertsNewestFirst(dbResults)
			results = paginateAlerts(dbResults, filter.Offset, filter.Limit)
		}
	}

	return results, nil
}

// listInMemory returns snapshots of the page of in-memory alerts selected by
// filter, newest first, and the number of alerts that matched before
// pagination. Only the alerts on the returned page are copied.
func (m *Manager) listInMemory(filter AlertFilter) ([]*Alert, int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matched []*Alert
	for _, alert := range m.alerts {
		if filter.matches(alert) {
			matched = append(matched, alert)
		}
	}
	sortAlertsNewestFirst(matched)

	page := paginateAlerts(matched, filter.Offset, filter.Limit)
	for i, alert := range page {
		page[i] = alert.clone()
	}
	return page, len(matched)
}

// sortAlertsNewestFirst orders alerts by creation time, newest first. Alerts
// created at the same time are ordered by ID so that pagination is stable
// between requests.
func sortAlertsNewestFirst(alerts []*Alert) {
	sort.Slice(alerts, func(i, j int) bool {
		if !alerts[i].CreatedAt.Equal(alerts[j].CreatedAt) {
			return alerts[i].CreatedAt.After(alerts[j].CreatedAt)
		}
		return bytes.Compare(alerts[i].ID[:], alerts[j].ID[:]) < 0
	})
}

// paginateAlerts returns the page of alerts selected by offset and limit
// (limit <= 0 means no limit). The result may share its backing array with
// alerts.
func paginateAlerts(alerts []*Alert, offset, limit int) []*Alert {
	if offset > 0 {
		if offset >= len(alerts) {
			return []*Alert{}
		}
		alerts = alerts[offset:]
	}
	if limit > 0 && limit < len(alerts) {
		alerts = alerts[:limit]
	}
	return alerts
}

// AlertFilter defines filters for listing alerts.
type AlertFilter struct {
	Status   *AlertStatus
	Severity *correlation.Severity
	RuleID   string
	Since    *time.Time
	Until    *time.Time
	Limit    int
	Offset   int
}

func (f *AlertFilter) matches(alert *Alert) bool {
	if f.Status != nil && alert.Status != *f.Status {
		return false
	}
	if f.Severity != nil && alert.Severity != *f.Severity {
		return false
	}
	if f.RuleID != "" && alert.RuleID != f.RuleID {
		return false
	}
	if f.Since != nil && alert.CreatedAt.Before(*f.Since) {
		return false
	}
	if f.Until != nil && alert.CreatedAt.After(*f.Until) {
		return false
	}
	return true
}

// Alert lifecycle. Valid transitions:
//
//	acknowledge: new, suppressed                         -> acknowledged
//	assign:      new, suppressed, acknowledged, in_progress -> in_progress
//	resolve:     any status except resolved              -> resolved
//
// Resolved is terminal. Notes can be added in any status. A rejected
// transition returns ErrInvalidTransition and leaves the alert unchanged.

func transitionError(id uuid.UUID, action string, from AlertStatus) error {
	return fmt.Errorf("%w: cannot %s alert %s in status %q", ErrInvalidTransition, action, id, from)
}

// nextUpdateTime returns the UpdatedAt for a new version of an alert whose
// previous version was stamped prev. The result has microsecond precision
// (the resolution of the alerts table) and is strictly later than prev, so
// the newest persisted version always sorts last by updated_at.
func nextUpdateTime(prev time.Time) time.Time {
	now := time.Now().UTC().Truncate(time.Microsecond)
	if !now.After(prev) {
		now = prev.UTC().Truncate(time.Microsecond).Add(time.Microsecond)
	}
	return now
}

// updateAlert applies fn to the alert under the manager lock and persists the
// resulting version. fn must validate before mutating: if it returns an error
// the alert is left untouched and nothing is written.
//
// The in-memory alert is the source of truth, so once fn has applied the
// change the call succeeds even if writing it to the database fails: the
// alert is queued and its latest version written later (see store). The
// write error used to be returned with the change applied anyway, so the API
// answered 500 for an action that had taken effect, a retry got 409, and the
// change was never persisted. Now the caller sees the state it asked for,
// and repeating the action is judged against that state, as it would be
// once stored (a second acknowledge is ErrInvalidTransition).
//
// An error is returned only when the alert is unknown, fn rejects the
// change, or the alert is not in memory and cannot be loaded from the
// database; nothing has changed then.
func (m *Manager) updateAlert(ctx context.Context, id uuid.UUID, action string, fn func(alert *Alert, now time.Time) error) error {
	if err := m.ensureLoaded(ctx, id); err != nil {
		return err
	}

	m.mu.Lock()
	alert, ok := m.alerts[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrAlertNotFound, id)
	}
	now := nextUpdateTime(alert.UpdatedAt)
	if err := fn(alert, now); err != nil {
		m.mu.Unlock()
		return err
	}
	alert.UpdatedAt = now
	snapshot := alert.clone()
	m.mu.Unlock()

	m.store(ctx, snapshot, action)
	return nil
}

// ensureLoaded brings an alert that exists only in the database (for
// example an old alert not restored by LoadFromDB) into memory so that it
// can be updated like any other alert.
func (m *Manager) ensureLoaded(ctx context.Context, id uuid.UUID) error {
	m.mu.RLock()
	_, inMemory := m.alerts[id]
	m.mu.RUnlock()
	if inMemory || m.db == nil {
		return nil
	}

	alert, err := m.loadAlert(ctx, id)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if _, exists := m.alerts[id]; !exists {
		m.alerts[id] = alert
	}
	m.mu.Unlock()
	return nil
}

// AcknowledgeAlert acknowledges an alert.
func (m *Manager) AcknowledgeAlert(ctx context.Context, id uuid.UUID, user string) error {
	return m.updateAlert(ctx, id, "acknowledge", func(alert *Alert, now time.Time) error {
		if alert.Status != StatusNew && alert.Status != StatusSuppressed {
			return transitionError(id, "acknowledge", alert.Status)
		}
		alert.Status = StatusAcknowledged
		alert.AckedAt = &now
		alert.AckedBy = user
		return nil
	})
}

// ResolveAlert resolves an alert.
func (m *Manager) ResolveAlert(ctx context.Context, id uuid.UUID, user string) error {
	return m.updateAlert(ctx, id, "resolve", func(alert *Alert, now time.Time) error {
		if alert.Status == StatusResolved {
			return transitionError(id, "resolve", alert.Status)
		}
		alert.Status = StatusResolved
		alert.ResolvedAt = &now
		alert.ResolvedBy = user
		return nil
	})
}

// AddNote adds a note to an alert.
func (m *Manager) AddNote(ctx context.Context, alertID uuid.UUID, author, content string) error {
	return m.updateAlert(ctx, alertID, "add note", func(alert *Alert, now time.Time) error {
		alert.Notes = append(alert.Notes, Note{
			ID:        uuid.New(),
			Author:    author,
			Content:   content,
			CreatedAt: now,
		})
		return nil
	})
}

// AssignAlert assigns an alert to a user.
func (m *Manager) AssignAlert(ctx context.Context, id uuid.UUID, assignee string) error {
	return m.updateAlert(ctx, id, "assign", func(alert *Alert, _ time.Time) error {
		if alert.Status == StatusResolved {
			return transitionError(id, "assign", alert.Status)
		}
		alert.AssignedTo = assignee
		alert.Status = StatusInProgress
		return nil
	})
}

// Stats returns alert statistics.
func (m *Manager) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	statusCounts := make(map[string]int)
	severityCounts := make(map[string]int)
	open := 0

	for _, alert := range m.alerts {
		statusCounts[string(alert.Status)]++
		severityCounts[string(alert.Severity)]++
		switch alert.Status {
		case StatusNew, StatusAcknowledged, StatusInProgress:
			open++
		}
	}

	stats := map[string]interface{}{
		"total": len(m.alerts),
		// open counts the alerts still to be worked: new, acknowledged or
		// in progress (not resolved or suppressed).
		"open":        open,
		"by_status":   statusCounts,
		"by_severity": severityCounts,
		"channels":    len(m.channels),
	}

	return stats
}

// Cleanup removes old resolved alerts from memory. An alert whose latest
// change is not yet in the database is kept until it is, since memory holds
// its only copy.
func (m *Manager) Cleanup(ctx context.Context) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-m.config.RetentionPeriod)
	removed := 0

	for id, alert := range m.alerts {
		if _, unsaved := m.pending[id]; unsaved {
			continue
		}
		if alert.CreatedAt.Before(cutoff) && alert.Status == StatusResolved {
			delete(m.alerts, id)
			removed++
		}
	}

	// Cleanup dedup map
	for key, entry := range m.dedup {
		if time.Since(entry.last) > m.config.DeduplicationWindow*2 {
			delete(m.dedup, key)
		}
	}

	return removed
}
