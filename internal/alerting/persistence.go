package alerting

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"boundary-siem/internal/correlation"

	"github.com/google/uuid"
)

// Alert persistence targets the ClickHouse "alerts" table created by
// internal/storage/migrations/004_create_alerts.sql, through the
// database/sql handle returned by storage.ClickHouseClient.DB().
//
// The table is a ReplacingMergeTree(updated_at). Migration 004 put status in
// its sorting key, which ClickHouse cannot UPDATE (storage.fixAlertsSortingKey
// rebuilds the table without it). Every change is therefore written as a
// complete new version of the row with a strictly increasing updated_at, and
// every read selects the newest version of each alert (ORDER BY updated_at
// DESC LIMIT 1 BY alert_id) before filtering. Older versions collapse during
// background merges. Writing the same version again changes nothing a read
// can see, which is what lets a failed write be retried (see pending.go).
//
// The table has no tags or MITRE columns, so those are stored together with
// the alert's metadata in the metadata column (see persistedMetadata).

// maxPersistedEventIDs caps the sample_event_ids column; event_count keeps
// the full count.
const maxPersistedEventIDs = 100

// dbTimeLayout formats timestamps for the DateTime64(6, 'UTC') columns.
// Values are bound as strings because the driver's positional binding
// truncates time.Time arguments to whole seconds, which would make versions
// written within the same second indistinguishable.
const dbTimeLayout = "2006-01-02 15:04:05.000000"

const alertInsertQuery = `INSERT INTO alerts (
	alert_id, rule_id, rule_name, severity, status, title, description,
	created_at, updated_at, acknowledged_at, resolved_at,
	acknowledged_by, resolved_by, assignee,
	group_key, event_count, sample_event_ids, metadata, notes
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// alertSelectColumns lists the columns scanned by scanAlert, in order.
const alertSelectColumns = `toString(alert_id), rule_id, rule_name, severity, status, title, description,
	created_at, updated_at, acknowledged_at, resolved_at,
	acknowledged_by, resolved_by, assignee,
	group_key, event_count, sample_event_ids, metadata, notes`

// persistedMetadata is the JSON document stored in the metadata column.
type persistedMetadata struct {
	Fields map[string]interface{}    `json:"fields,omitempty"`
	Tags   []string                  `json:"tags,omitempty"`
	MITRE  *correlation.MITREMapping `json:"mitre,omitempty"`
}

func formatDBTime(t time.Time) string {
	return t.UTC().Format(dbTimeLayout)
}

func formatDBTimePtr(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return formatDBTime(*t)
}

// persistAlert writes a new version of an alert. alert must be a snapshot
// that no other goroutine modifies.
func (m *Manager) persistAlert(ctx context.Context, alert *Alert) error {
	sampleIDs := alert.EventIDs
	if len(sampleIDs) > maxPersistedEventIDs {
		sampleIDs = sampleIDs[:maxPersistedEventIDs]
	}
	eventIDs := make([]string, len(sampleIDs))
	for i, id := range sampleIDs {
		eventIDs[i] = id.String()
	}

	metadataJSON, err := json.Marshal(persistedMetadata{
		Fields: alert.Metadata,
		Tags:   alert.Tags,
		MITRE:  alert.MITRE,
	})
	if err != nil {
		slog.Warn("failed to marshal metadata, using empty object", "alert_id", alert.ID, "error", err)
		metadataJSON = []byte("{}")
	}
	notes := alert.Notes
	if notes == nil {
		notes = []Note{}
	}
	notesJSON, err := json.Marshal(notes)
	if err != nil {
		slog.Warn("failed to marshal notes, using empty array", "alert_id", alert.ID, "error", err)
		notesJSON = []byte("[]")
	}

	eventCount := max(alert.EventCount, 0)

	_, err = m.db.ExecContext(ctx, alertInsertQuery,
		alert.ID.String(),
		alert.RuleID,
		alert.RuleName,
		string(alert.Severity),
		string(alert.Status),
		alert.Title,
		alert.Description,
		formatDBTime(alert.CreatedAt),
		formatDBTime(alert.UpdatedAt),
		formatDBTimePtr(alert.AckedAt),
		formatDBTimePtr(alert.ResolvedAt),
		alert.AckedBy,
		alert.ResolvedBy,
		alert.AssignedTo,
		alert.GroupKey,
		eventCount, // bound as a numeric literal into the UInt32 column
		eventIDs,
		string(metadataJSON),
		string(notesJSON),
	)
	if err != nil {
		return fmt.Errorf("failed to persist alert %s: %w", alert.ID, err)
	}
	return nil
}

// latestAlertsQuery returns a query selecting the newest version of every
// alert that satisfies preFilter (conditions on columns that never change
// between versions), then keeping those that satisfy postFilter.
func latestAlertsQuery(preFilter, postFilter []string) string {
	var b strings.Builder
	b.WriteString("SELECT ")
	b.WriteString(alertSelectColumns)
	b.WriteString(" FROM (SELECT * FROM alerts")
	if len(preFilter) > 0 {
		b.WriteString(" WHERE ")
		b.WriteString(strings.Join(preFilter, " AND "))
	}
	b.WriteString(" ORDER BY updated_at DESC LIMIT 1 BY alert_id)")
	if len(postFilter) > 0 {
		b.WriteString(" WHERE ")
		b.WriteString(strings.Join(postFilter, " AND "))
	}
	return b.String()
}

// loadAlert loads the latest version of an alert from the database.
func (m *Manager) loadAlert(ctx context.Context, id uuid.UUID) (*Alert, error) {
	query := latestAlertsQuery([]string{"alert_id = toUUID(?)"}, nil)
	alert, err := scanAlert(m.db.QueryRowContext(ctx, query, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrAlertNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load alert %s: %w", id, err)
	}
	return alert, nil
}

// listAlertsFromDB queries the latest version of alerts matching the filter.
func (m *Manager) listAlertsFromDB(ctx context.Context, filter AlertFilter) ([]*Alert, error) {
	// Rule, severity and creation time never change between versions, so
	// they can be applied before picking the newest version; status must be
	// checked on the newest version only.
	var pre, post []string
	var args []interface{}

	if filter.Severity != nil {
		pre = append(pre, "severity = ?")
		args = append(args, string(*filter.Severity))
	}
	if filter.RuleID != "" {
		pre = append(pre, "rule_id = ?")
		args = append(args, filter.RuleID)
	}
	if filter.Since != nil {
		pre = append(pre, "created_at >= toDateTime64(?, 6, 'UTC')")
		args = append(args, formatDBTime(*filter.Since))
	}
	if filter.Until != nil {
		pre = append(pre, "created_at <= toDateTime64(?, 6, 'UTC')")
		args = append(args, formatDBTime(*filter.Until))
	}
	if filter.Status != nil {
		post = append(post, "status = ?")
		args = append(args, string(*filter.Status))
	}

	// Same order as sortAlertsNewestFirst (the canonical UUID string sorts
	// like its bytes), so that LIMIT selects the alerts of the requested page
	// even when several share a creation time.
	query := latestAlertsQuery(pre, post) + " ORDER BY created_at DESC, toString(alert_id) ASC"
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Offset+filter.Limit)
	}
	return m.queryAlerts(ctx, query, args...)
}

// LoadFromDB loads persisted alerts into memory so that open alerts and
// their lifecycle survive a restart. It loads the latest version of every
// unresolved alert and of resolved alerts created within RetentionPeriod,
// newest first and at most MaxAlerts (when positive). Alerts already in
// memory are kept as they are. The deduplication window is seeded from the
// loaded alerts, so a restart does not re-raise alerts that were just
// raised. It returns the number of alerts added to memory. It is a no-op
// without a database.
func (m *Manager) LoadFromDB(ctx context.Context) (int, error) {
	if m.db == nil {
		return 0, nil
	}

	cutoff := time.Now().Add(-m.config.RetentionPeriod)
	query := latestAlertsQuery(nil, []string{"(status != ? OR created_at >= toDateTime64(?, 6, 'UTC'))"}) +
		" ORDER BY created_at DESC"
	args := []interface{}{string(StatusResolved), formatDBTime(cutoff)}
	if m.config.MaxAlerts > 0 {
		query += " LIMIT ?"
		args = append(args, m.config.MaxAlerts)
	}

	alerts, err := m.queryAlerts(ctx, query, args...)
	if err != nil {
		return 0, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	loaded := 0
	for _, alert := range alerts {
		if _, exists := m.alerts[alert.ID]; exists {
			continue
		}
		m.alerts[alert.ID] = alert
		loaded++

		// The newest alert of each rule and group; a recurrence within the
		// window is merged into it unless it has been resolved.
		dedupKey := dedupKeyOf(alert.RuleID, alert.GroupKey)
		if entry, ok := m.dedup[dedupKey]; !ok || alert.UpdatedAt.After(entry.last) {
			m.dedup[dedupKey] = dedupEntry{alertID: alert.ID, last: alert.UpdatedAt}
		}
	}
	slog.Info("loaded alerts from database", "count", loaded)
	return loaded, nil
}

func (m *Manager) queryAlerts(ctx context.Context, query string, args ...interface{}) ([]*Alert, error) {
	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query alerts: %w", err)
	}
	defer rows.Close()

	var results []*Alert
	for rows.Next() {
		alert, err := scanAlert(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan alert: %w", err)
		}
		results = append(results, alert)
	}
	return results, rows.Err()
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

// scanAlert scans one row selected with alertSelectColumns.
func scanAlert(row rowScanner) (*Alert, error) {
	var (
		alert                                     Alert
		id, severity, status, metadataJSON, notes string
		ackedAt, resolvedAt                       sql.NullTime
		eventCount                                int64
		eventIDs                                  []string
	)
	err := row.Scan(
		&id, &alert.RuleID, &alert.RuleName, &severity, &status, &alert.Title, &alert.Description,
		&alert.CreatedAt, &alert.UpdatedAt, &ackedAt, &resolvedAt,
		&alert.AckedBy, &alert.ResolvedBy, &alert.AssignedTo,
		&alert.GroupKey, &eventCount, &eventIDs, &metadataJSON, &notes,
	)
	if err != nil {
		return nil, err
	}

	if alert.ID, err = uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("invalid alert_id %q: %w", id, err)
	}
	alert.Severity = correlation.Severity(severity)
	alert.Status = AlertStatus(status)
	alert.EventCount = int(eventCount)
	if ackedAt.Valid {
		t := ackedAt.Time
		alert.AckedAt = &t
	}
	if resolvedAt.Valid {
		t := resolvedAt.Time
		alert.ResolvedAt = &t
	}

	for _, s := range eventIDs {
		eventID, err := uuid.Parse(s)
		if err != nil {
			slog.Warn("skipping invalid event ID", "alert_id", alert.ID, "event_id", s)
			continue
		}
		alert.EventIDs = append(alert.EventIDs, eventID)
	}

	if metadataJSON != "" {
		var meta persistedMetadata
		if err := json.Unmarshal([]byte(metadataJSON), &meta); err != nil {
			slog.Warn("failed to unmarshal metadata", "alert_id", alert.ID, "error", err)
		} else {
			alert.Tags = meta.Tags
			alert.MITRE = meta.MITRE
			alert.Metadata = meta.Fields
		}
	}
	if alert.Metadata == nil {
		alert.Metadata = make(map[string]interface{})
	}
	if notes != "" {
		if err := json.Unmarshal([]byte(notes), &alert.Notes); err != nil {
			slog.Warn("failed to unmarshal notes", "alert_id", alert.ID, "error", err)
		}
		if len(alert.Notes) == 0 {
			alert.Notes = nil
		}
	}

	return &alert, nil
}
