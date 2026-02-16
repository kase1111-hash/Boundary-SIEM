// Package alerting provides alert management and notification capabilities.
package alerting

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
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
type Manager struct {
	config   ManagerConfig
	db       *sql.DB
	channels []NotificationChannel
	alerts   map[uuid.UUID]*Alert
	dedup    map[string]time.Time // rule_id+group_key -> last alert time
	mu       sync.RWMutex
}

// NewManager creates a new alert manager.
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

	alert := &Alert{
		ID:          corrAlert.ID,
		RuleID:      corrAlert.RuleID,
		RuleName:    corrAlert.RuleName,
		Severity:    correlation.IntToSeverity(corrAlert.Severity),
		Status:      StatusNew,
		Title:       corrAlert.Title,
		Description: corrAlert.Description,
		CreatedAt:   corrAlert.Timestamp,
		UpdatedAt:   corrAlert.Timestamp,
		GroupKey:    corrAlert.GroupKey,
		EventCount:  len(corrAlert.Events),
		EventIDs:    eventIDs,
		Tags:        corrAlert.Tags,
		MITRE:       corrAlert.MITRE,
		Metadata:    make(map[string]interface{}),
	}

	// Store alert
	if err := m.storeAlert(ctx, alert); err != nil {
		slog.Error("failed to store alert", "error", err)
	}

	// Send notifications
	m.sendNotifications(ctx, alert)

	return nil
}

// storeAlert stores an alert in memory and database.
func (m *Manager) storeAlert(ctx context.Context, alert *Alert) error {
	m.mu.Lock()
	m.alerts[alert.ID] = alert
	m.mu.Unlock()

	// Store to database if available
	if m.db != nil {
		return m.persistAlert(ctx, alert)
	}
	return nil
}

// persistAlert persists an alert to the database.
func (m *Manager) persistAlert(ctx context.Context, alert *Alert) error {
	eventIDsJSON, err := json.Marshal(alert.EventIDs)
	if err != nil {
		slog.Warn("failed to marshal event IDs, using empty array", "alert_id", alert.ID, "error", err)
		eventIDsJSON = []byte("[]")
	}
	tagsJSON, err := json.Marshal(alert.Tags)
	if err != nil {
		slog.Warn("failed to marshal tags, using empty array", "alert_id", alert.ID, "error", err)
		tagsJSON = []byte("[]")
	}
	metadataJSON, err := json.Marshal(alert.Metadata)
	if err != nil {
		slog.Warn("failed to marshal metadata, using empty object", "alert_id", alert.ID, "error", err)
		metadataJSON = []byte("{}")
	}
	mitreJSON, err := json.Marshal(alert.MITRE)
	if err != nil {
		slog.Warn("failed to marshal MITRE data, using null", "alert_id", alert.ID, "error", err)
		mitreJSON = []byte("null")
	}

	query := `
		INSERT INTO alerts (
			id, rule_id, rule_name, severity, status, title, description,
			created_at, updated_at, group_key, event_count, event_ids,
			tags, mitre, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = m.db.ExecContext(ctx, query,
		alert.ID.String(),
		alert.RuleID,
		alert.RuleName,
		string(alert.Severity),
		string(alert.Status),
		alert.Title,
		alert.Description,
		alert.CreatedAt,
		alert.UpdatedAt,
		alert.GroupKey,
		alert.EventCount,
		string(eventIDsJSON),
		string(tagsJSON),
		string(mitreJSON),
		string(metadataJSON),
	)
	return err
}

// sendNotifications sends alert to all channels.
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

// GetAlert retrieves an alert by ID.
func (m *Manager) GetAlert(ctx context.Context, id uuid.UUID) (*Alert, error) {
	m.mu.RLock()
	if alert, ok := m.alerts[id]; ok {
		m.mu.RUnlock()
		return alert, nil
	}
	m.mu.RUnlock()

	// Try database
	if m.db != nil {
		return m.loadAlert(ctx, id)
	}
	return nil, fmt.Errorf("alert not found: %s", id)
}

// loadAlert loads an alert from the database.
func (m *Manager) loadAlert(ctx context.Context, id uuid.UUID) (*Alert, error) {
	query := `
		SELECT
			id, rule_id, rule_name, severity, status, title, description,
			created_at, updated_at, acked_at, acked_by, resolved_at, resolved_by,
			group_key, event_count, event_ids, tags, mitre, metadata, assigned_to
		FROM alerts
		WHERE id = ?
	`

	var alert Alert
	var severity, status string
	var eventIDsJSON, tagsJSON, mitreJSON, metadataJSON sql.NullString
	var ackedAt, resolvedAt sql.NullTime
	var ackedBy, resolvedBy, assignedTo sql.NullString

	err := m.db.QueryRowContext(ctx, query, id.String()).Scan(
		&alert.ID,
		&alert.RuleID,
		&alert.RuleName,
		&severity,
		&status,
		&alert.Title,
		&alert.Description,
		&alert.CreatedAt,
		&alert.UpdatedAt,
		&ackedAt,
		&ackedBy,
		&resolvedAt,
		&resolvedBy,
		&alert.GroupKey,
		&alert.EventCount,
		&eventIDsJSON,
		&tagsJSON,
		&mitreJSON,
		&metadataJSON,
		&assignedTo,
	)
	if err != nil {
		return nil, err
	}

	alert.Severity = correlation.Severity(severity)
	alert.Status = AlertStatus(status)
	if ackedAt.Valid {
		alert.AckedAt = &ackedAt.Time
	}
	alert.AckedBy = ackedBy.String
	if resolvedAt.Valid {
		alert.ResolvedAt = &resolvedAt.Time
	}
	alert.ResolvedBy = resolvedBy.String
	alert.AssignedTo = assignedTo.String

	if eventIDsJSON.Valid {
		if err := json.Unmarshal([]byte(eventIDsJSON.String), &alert.EventIDs); err != nil {
			slog.Warn("failed to unmarshal event IDs", "alert_id", alert.ID, "error", err)
		}
	}
	if tagsJSON.Valid {
		if err := json.Unmarshal([]byte(tagsJSON.String), &alert.Tags); err != nil {
			slog.Warn("failed to unmarshal tags", "alert_id", alert.ID, "error", err)
		}
	}
	if metadataJSON.Valid {
		if err := json.Unmarshal([]byte(metadataJSON.String), &alert.Metadata); err != nil {
			slog.Warn("failed to unmarshal metadata", "alert_id", alert.ID, "error", err)
		}
	}

	return &alert, nil
}

// ListAlerts lists alerts with optional filters.
// Falls back to database if in-memory store has no results and DB is available.
func (m *Manager) ListAlerts(ctx context.Context, filter AlertFilter) ([]*Alert, error) {
	m.mu.RLock()

	var results []*Alert
	for _, alert := range m.alerts {
		if filter.matches(alert) {
			results = append(results, alert)
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
	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].CreatedAt.After(results[i].CreatedAt) {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

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

// listAlertsFromDB queries alerts from the database with filters.
func (m *Manager) listAlertsFromDB(ctx context.Context, filter AlertFilter) ([]*Alert, error) {
	query := `
		SELECT
			id, rule_id, rule_name, severity, status, title, description,
			created_at, updated_at, acked_at, acked_by, resolved_at, resolved_by,
			group_key, event_count, event_ids, tags, mitre, metadata, assigned_to
		FROM alerts
		WHERE 1=1
	`
	var args []interface{}

	if filter.Status != nil {
		query += " AND status = ?"
		args = append(args, string(*filter.Status))
	}
	if filter.Severity != nil {
		query += " AND severity = ?"
		args = append(args, string(*filter.Severity))
	}
	if filter.RuleID != "" {
		query += " AND rule_id = ?"
		args = append(args, filter.RuleID)
	}
	if filter.Since != nil {
		query += " AND created_at >= ?"
		args = append(args, *filter.Since)
	}
	if filter.Until != nil {
		query += " AND created_at <= ?"
		args = append(args, *filter.Until)
	}

	query += " ORDER BY created_at DESC"

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query alerts: %w", err)
	}
	defer rows.Close()

	var results []*Alert
	for rows.Next() {
		var alert Alert
		var severity, status string
		var eventIDsJSON, tagsJSON, mitreJSON, metadataJSON sql.NullString
		var ackedAt, resolvedAt sql.NullTime
		var ackedBy, resolvedBy, assignedTo sql.NullString

		err := rows.Scan(
			&alert.ID, &alert.RuleID, &alert.RuleName,
			&severity, &status, &alert.Title, &alert.Description,
			&alert.CreatedAt, &alert.UpdatedAt,
			&ackedAt, &ackedBy, &resolvedAt, &resolvedBy,
			&alert.GroupKey, &alert.EventCount,
			&eventIDsJSON, &tagsJSON, &mitreJSON, &metadataJSON,
			&assignedTo,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan alert: %w", err)
		}

		alert.Severity = correlation.Severity(severity)
		alert.Status = AlertStatus(status)
		if ackedAt.Valid {
			alert.AckedAt = &ackedAt.Time
		}
		alert.AckedBy = ackedBy.String
		if resolvedAt.Valid {
			alert.ResolvedAt = &resolvedAt.Time
		}
		alert.ResolvedBy = resolvedBy.String
		alert.AssignedTo = assignedTo.String

		if eventIDsJSON.Valid {
			if err := json.Unmarshal([]byte(eventIDsJSON.String), &alert.EventIDs); err != nil {
				slog.Warn("failed to unmarshal event IDs", "alert_id", alert.ID, "error", err)
			}
		}
		if tagsJSON.Valid {
			if err := json.Unmarshal([]byte(tagsJSON.String), &alert.Tags); err != nil {
				slog.Warn("failed to unmarshal tags", "alert_id", alert.ID, "error", err)
			}
		}
		if metadataJSON.Valid {
			if err := json.Unmarshal([]byte(metadataJSON.String), &alert.Metadata); err != nil {
				slog.Warn("failed to unmarshal metadata", "alert_id", alert.ID, "error", err)
			}
		}

		results = append(results, &alert)
	}

	return results, rows.Err()
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

// AcknowledgeAlert acknowledges an alert.
func (m *Manager) AcknowledgeAlert(ctx context.Context, id uuid.UUID, user string) error {
	m.mu.Lock()
	alert, ok := m.alerts[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("alert not found: %s", id)
	}

	now := time.Now()
	alert.Status = StatusAcknowledged
	alert.AckedAt = &now
	alert.AckedBy = user
	alert.UpdatedAt = now
	m.mu.Unlock()

	if m.db != nil {
		query := `
			UPDATE alerts
			SET status = ?, acked_at = ?, acked_by = ?, updated_at = ?
			WHERE id = ?
		`
		_, err := m.db.ExecContext(ctx, query, StatusAcknowledged, now, user, now, id.String())
		return err
	}
	return nil
}

// ResolveAlert resolves an alert.
func (m *Manager) ResolveAlert(ctx context.Context, id uuid.UUID, user string) error {
	m.mu.Lock()
	alert, ok := m.alerts[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("alert not found: %s", id)
	}

	now := time.Now()
	alert.Status = StatusResolved
	alert.ResolvedAt = &now
	alert.ResolvedBy = user
	alert.UpdatedAt = now
	m.mu.Unlock()

	if m.db != nil {
		query := `
			UPDATE alerts
			SET status = ?, resolved_at = ?, resolved_by = ?, updated_at = ?
			WHERE id = ?
		`
		_, err := m.db.ExecContext(ctx, query, StatusResolved, now, user, now, id.String())
		return err
	}
	return nil
}

// AddNote adds a note to an alert.
func (m *Manager) AddNote(ctx context.Context, alertID uuid.UUID, author, content string) error {
	m.mu.Lock()
	alert, ok := m.alerts[alertID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("alert not found: %s", alertID)
	}

	note := Note{
		ID:        uuid.New(),
		Author:    author,
		Content:   content,
		CreatedAt: time.Now(),
	}
	alert.Notes = append(alert.Notes, note)
	alert.UpdatedAt = time.Now()
	m.mu.Unlock()

	return nil
}

// AssignAlert assigns an alert to a user.
func (m *Manager) AssignAlert(ctx context.Context, id uuid.UUID, assignee string) error {
	m.mu.Lock()
	alert, ok := m.alerts[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("alert not found: %s", id)
	}

	alert.AssignedTo = assignee
	alert.Status = StatusInProgress
	alert.UpdatedAt = time.Now()
	m.mu.Unlock()

	if m.db != nil {
		query := `
			UPDATE alerts
			SET assigned_to = ?, status = ?, updated_at = ?
			WHERE id = ?
		`
		_, err := m.db.ExecContext(ctx, query, assignee, StatusInProgress, time.Now(), id.String())
		return err
	}
	return nil
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
