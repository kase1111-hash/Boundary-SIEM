// Package alerting provides alert management and notification capabilities.
package alerting

import (
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
}

// DefaultManagerConfig returns default manager configuration.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		DeduplicationWindow: 15 * time.Minute,
		RetentionPeriod:     30 * 24 * time.Hour, // 30 days
		MaxAlerts:           100000,
	}
}

// Manager manages alerts and notifications.
//
// Alerts are held in memory and, when db is non-nil, persisted to the
// ClickHouse "alerts" table (see persistence.go). Every accessor returns a
// snapshot (deep copy) of an alert, so callers may read or encode it without
// holding the manager's lock while lifecycle methods mutate the original.
type Manager struct {
	config   ManagerConfig
	db       *sql.DB
	channels []NotificationChannel
	alerts   map[uuid.UUID]*Alert
	dedup    map[string]time.Time // rule_id+group_key -> last alert time
	mu       sync.RWMutex
}

// NewManager creates a new alert manager. db is the database/sql handle of
// the ClickHouse store (storage.ClickHouseClient.DB()); pass nil to keep
// alerts in memory only.
func NewManager(config ManagerConfig, db *sql.DB) *Manager {
	return &Manager{
		config:   config,
		db:       db,
		channels: make([]NotificationChannel, 0),
		alerts:   make(map[uuid.UUID]*Alert),
		dedup:    make(map[string]time.Time),
	}
}

// AddChannel adds a notification channel.
func (m *Manager) AddChannel(channel NotificationChannel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.channels = append(m.channels, channel)
	slog.Info("added notification channel", "name", channel.Name())
}

// HandleCorrelationAlert handles an alert from the correlation engine.
func (m *Manager) HandleCorrelationAlert(ctx context.Context, corrAlert *correlation.Alert) error {
	// Check for deduplication
	dedupKey := fmt.Sprintf("%s:%s", corrAlert.RuleID, corrAlert.GroupKey)

	m.mu.Lock()
	if lastTime, ok := m.dedup[dedupKey]; ok {
		if time.Since(lastTime) < m.config.DeduplicationWindow {
			m.mu.Unlock()
			slog.Debug("suppressing duplicate alert", "rule_id", corrAlert.RuleID)
			return nil
		}
	}
	m.dedup[dedupKey] = time.Now()
	m.mu.Unlock()

	// Convert to managed alert
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

	alert := &Alert{
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

	// Store alert
	snapshot, err := m.storeAlert(ctx, alert)
	if err != nil {
		slog.Error("failed to store alert", "error", err)
	}

	// Send notifications
	m.sendNotifications(ctx, snapshot)

	return nil
}

// storeAlert stores an alert in memory and database. It returns a snapshot
// of the stored alert taken before any other goroutine could modify it.
func (m *Manager) storeAlert(ctx context.Context, alert *Alert) (*Alert, error) {
	m.mu.Lock()
	m.alerts[alert.ID] = alert
	snapshot := alert.clone()
	m.mu.Unlock()

	// Store to database if available
	if m.db != nil {
		return snapshot, m.persistAlert(ctx, snapshot)
	}
	return snapshot, nil
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

// ListAlerts lists snapshots of alerts with optional filters.
// Falls back to database if in-memory store has no results and DB is available.
func (m *Manager) ListAlerts(ctx context.Context, filter AlertFilter) ([]*Alert, error) {
	m.mu.RLock()

	var results []*Alert
	for _, alert := range m.alerts {
		if filter.matches(alert) {
			results = append(results, alert.clone())
		}
	}
	m.mu.RUnlock()

	// Fall back to database if in-memory store is empty and DB is available
	if len(results) == 0 && m.db != nil {
		dbResults, err := m.listAlertsFromDB(ctx, filter)
		if err != nil {
			slog.Warn("failed to list alerts from database, returning in-memory results", "error", err)
		} else {
			results = dbResults
		}
	}

	// Sort by created_at desc
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})

	// Apply pagination
	if filter.Offset > 0 {
		if filter.Offset >= len(results) {
			return []*Alert{}, nil
		}
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	return results, nil
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
// the alert is left untouched and nothing is written. The in-memory change
// stays applied even if persisting it fails; the error is returned and the
// next successful write of the alert (which stores the full row) repairs the
// database copy.
func (m *Manager) updateAlert(ctx context.Context, id uuid.UUID, fn func(alert *Alert, now time.Time) error) error {
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

	if m.db != nil {
		return m.persistAlert(ctx, snapshot)
	}
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
	return m.updateAlert(ctx, id, func(alert *Alert, now time.Time) error {
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
	return m.updateAlert(ctx, id, func(alert *Alert, now time.Time) error {
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
	return m.updateAlert(ctx, alertID, func(alert *Alert, now time.Time) error {
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
	return m.updateAlert(ctx, id, func(alert *Alert, _ time.Time) error {
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

	for _, alert := range m.alerts {
		statusCounts[string(alert.Status)]++
		severityCounts[string(alert.Severity)]++
	}

	stats := map[string]interface{}{
		"total":       len(m.alerts),
		"by_status":   statusCounts,
		"by_severity": severityCounts,
		"channels":    len(m.channels),
	}

	return stats
}

// Cleanup removes old alerts.
func (m *Manager) Cleanup(ctx context.Context) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-m.config.RetentionPeriod)
	removed := 0

	for id, alert := range m.alerts {
		if alert.CreatedAt.Before(cutoff) && alert.Status == StatusResolved {
			delete(m.alerts, id)
			removed++
		}
	}

	// Cleanup dedup map
	for key, t := range m.dedup {
		if time.Since(t) > m.config.DeduplicationWindow*2 {
			delete(m.dedup, key)
		}
	}

	return removed
}
