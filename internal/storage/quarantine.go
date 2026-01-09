package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// QuarantineEntry represents an invalid event stored in quarantine.
type QuarantineEntry struct {
	RawEvent         string
	SourceIP         string
	SourceFormat     string // "json" or "cef"
	ValidationErrors []string
	ErrorCode        string
}

// QuarantineWriter handles writing invalid events to the quarantine table.
type QuarantineWriter struct {
	client *ClickHouseClient
}

// NewQuarantineWriter creates a new QuarantineWriter.
func NewQuarantineWriter(client *ClickHouseClient) *QuarantineWriter {
	return &QuarantineWriter{client: client}
}

// Write stores a single quarantine entry.
func (qw *QuarantineWriter) Write(ctx context.Context, entry *QuarantineEntry) error {
	query := `
		INSERT INTO events_quarantine (
			quarantine_id, raw_event, source_ip, source_format,
			validation_errors, error_code
		) VALUES (?, ?, ?, ?, ?, ?)
	`

	return qw.client.Exec(ctx, query,
		uuid.New(),
		entry.RawEvent,
		entry.SourceIP,
		entry.SourceFormat,
		entry.ValidationErrors,
		entry.ErrorCode,
	)
}

// WriteBatch stores multiple quarantine entries.
func (qw *QuarantineWriter) WriteBatch(ctx context.Context, entries []*QuarantineEntry) error {
	if len(entries) == 0 {
		return nil
	}

	batch, err := qw.client.PrepareBatch(ctx, `
		INSERT INTO events_quarantine (
			quarantine_id, raw_event, source_ip, source_format,
			validation_errors, error_code
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare quarantine batch: %w", err)
	}

	for _, entry := range entries {
		err := batch.Append(
			uuid.New(),
			entry.RawEvent,
			entry.SourceIP,
			entry.SourceFormat,
			entry.ValidationErrors,
			entry.ErrorCode,
		)
		if err != nil {
			return fmt.Errorf("failed to append quarantine entry: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("failed to send quarantine batch: %w", err)
	}

	return nil
}

// QuarantinedEvent represents an event retrieved from quarantine.
type QuarantinedEvent struct {
	QuarantineID      uuid.UUID
	QuarantinedAt     time.Time
	RawEvent          string
	SourceIP          string
	SourceFormat      string
	ValidationErrors  []string
	ErrorCode         string
	ReprocessAttempts uint8
	Reprocessed       bool
}

// GetPendingReprocess returns quarantined events that haven't been reprocessed.
func (qw *QuarantineWriter) GetPendingReprocess(ctx context.Context, limit int) ([]QuarantinedEvent, error) {
	query := `
		SELECT
			quarantine_id, quarantined_at, raw_event, source_ip,
			source_format, validation_errors, error_code,
			reprocess_attempts, reprocessed
		FROM events_quarantine
		WHERE reprocessed = false AND reprocess_attempts < 3
		ORDER BY quarantined_at ASC
		LIMIT ?
	`

	rows, err := qw.client.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query quarantine: %w", err)
	}
	defer rows.Close()

	var entries []QuarantinedEvent
	for rows.Next() {
		var entry QuarantinedEvent
		if err := rows.Scan(
			&entry.QuarantineID,
			&entry.QuarantinedAt,
			&entry.RawEvent,
			&entry.SourceIP,
			&entry.SourceFormat,
			&entry.ValidationErrors,
			&entry.ErrorCode,
			&entry.ReprocessAttempts,
			&entry.Reprocessed,
		); err != nil {
			return nil, fmt.Errorf("failed to scan quarantine entry: %w", err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// MarkReprocessed marks a quarantine entry as reprocessed.
func (qw *QuarantineWriter) MarkReprocessed(ctx context.Context, quarantineID uuid.UUID, eventID uuid.UUID) error {
	query := `
		ALTER TABLE events_quarantine
		UPDATE
			reprocessed = true,
			reprocessed_at = now64(6),
			reprocessed_event_id = ?
		WHERE quarantine_id = ?
	`
	return qw.client.Exec(ctx, query, eventID, quarantineID)
}

// IncrementAttempt increments the reprocess attempt counter.
func (qw *QuarantineWriter) IncrementAttempt(ctx context.Context, quarantineID uuid.UUID) error {
	query := `
		ALTER TABLE events_quarantine
		UPDATE reprocess_attempts = reprocess_attempts + 1
		WHERE quarantine_id = ?
	`
	return qw.client.Exec(ctx, query, quarantineID)
}

// Count returns the number of events in quarantine.
func (qw *QuarantineWriter) Count(ctx context.Context) (uint64, error) {
	query := "SELECT count() FROM events_quarantine WHERE reprocessed = false"

	rows, err := qw.client.Query(ctx, query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var count uint64
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			return 0, err
		}
	}

	return count, nil
}
