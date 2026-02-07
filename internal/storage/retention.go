package storage

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// RetentionConfig holds configurable TTL settings for storage tables.
type RetentionConfig struct {
	EventsTTL     time.Duration
	CriticalTTL   time.Duration
	QuarantineTTL time.Duration
	AlertsTTL     time.Duration
}

// RetentionManager applies and manages data retention policies.
type RetentionManager struct {
	client *ClickHouseClient
	config RetentionConfig
}

// NewRetentionManager creates a new retention manager.
func NewRetentionManager(client *ClickHouseClient, config RetentionConfig) *RetentionManager {
	return &RetentionManager{
		client: client,
		config: config,
	}
}

// ApplyTTLs updates TTL settings on all tables to match the configured retention periods.
// This should be called after migrations have run.
func (r *RetentionManager) ApplyTTLs(ctx context.Context) error {
	type tablePolicy struct {
		table  string
		column string
		ttl    time.Duration
	}

	policies := []tablePolicy{
		{"events", "timestamp", r.config.EventsTTL},
		{"events_critical", "timestamp", r.config.CriticalTTL},
		{"quarantine", "quarantined_at", r.config.QuarantineTTL},
		{"alerts", "created_at", r.config.AlertsTTL},
	}

	for _, p := range policies {
		if p.ttl <= 0 {
			continue
		}

		days := int(p.ttl.Hours() / 24)
		if days < 1 {
			days = 1
		}

		query := fmt.Sprintf(
			"ALTER TABLE %s MODIFY TTL %s + INTERVAL %d DAY DELETE",
			p.table, p.column, days,
		)

		if err := r.client.Exec(ctx, query); err != nil {
			slog.Warn("failed to apply TTL policy",
				"table", p.table,
				"ttl_days", days,
				"error", err,
			)
			// Don't fail startup if a table doesn't exist yet
			continue
		}

		slog.Info("applied retention policy",
			"table", p.table,
			"ttl_days", days,
		)
	}

	return nil
}

// GetPartitions returns the list of partitions for a table.
func (r *RetentionManager) GetPartitions(ctx context.Context, table string) ([]PartitionInfo, error) {
	query := `
		SELECT
			partition,
			name,
			rows,
			bytes_on_disk,
			min_time,
			max_time
		FROM system.parts
		WHERE table = ? AND active = 1
		ORDER BY partition
	`

	rows, err := r.client.Query(ctx, query, table)
	if err != nil {
		return nil, fmt.Errorf("failed to query partitions: %w", err)
	}
	defer rows.Close()

	var partitions []PartitionInfo
	for rows.Next() {
		var p PartitionInfo
		if err := rows.Scan(&p.Partition, &p.Name, &p.Rows, &p.BytesOnDisk, &p.MinTime, &p.MaxTime); err != nil {
			return nil, fmt.Errorf("failed to scan partition: %w", err)
		}
		partitions = append(partitions, p)
	}

	return partitions, nil
}

// DropPartition drops a specific partition from a table.
func (r *RetentionManager) DropPartition(ctx context.Context, table, partition string) error {
	query := fmt.Sprintf("ALTER TABLE %s DROP PARTITION '%s'",
		sanitizeTableName(table), partition)

	if err := r.client.Exec(ctx, query); err != nil {
		return fmt.Errorf("failed to drop partition %s from %s: %w", partition, table, err)
	}

	slog.Info("dropped partition", "table", table, "partition", partition)
	return nil
}

// PartitionInfo holds information about a table partition.
type PartitionInfo struct {
	Partition   string    `json:"partition"`
	Name        string    `json:"name"`
	Rows        uint64    `json:"rows"`
	BytesOnDisk uint64    `json:"bytes_on_disk"`
	MinTime     time.Time `json:"min_time"`
	MaxTime     time.Time `json:"max_time"`
}

// sanitizeTableName ensures table name contains only safe characters.
func sanitizeTableName(name string) string {
	var result []byte
	for _, b := range []byte(name) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
			(b >= '0' && b <= '9') || b == '_' {
			result = append(result, b)
		}
	}
	return string(result)
}
