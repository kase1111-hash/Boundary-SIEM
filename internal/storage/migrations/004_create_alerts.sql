-- Migration: 004_create_alerts
-- Description: Create alerts table for persistent alert storage

CREATE TABLE IF NOT EXISTS alerts (
    -- Primary identifiers
    alert_id UUID,
    tenant_id LowCardinality(String) DEFAULT '',

    -- Rule reference
    rule_id String,
    rule_name String,
    rule_type LowCardinality(String),

    -- Alert details
    severity LowCardinality(String),
    title String,
    description String,
    status LowCardinality(String) DEFAULT 'open',

    -- Lifecycle timestamps
    created_at DateTime64(6, 'UTC'),
    updated_at DateTime64(6, 'UTC'),
    acknowledged_at Nullable(DateTime64(6, 'UTC')),
    resolved_at Nullable(DateTime64(6, 'UTC')),

    -- Assignment
    acknowledged_by String DEFAULT '',
    resolved_by String DEFAULT '',
    assignee String DEFAULT '',

    -- Context
    group_key String DEFAULT '',
    event_count UInt32 DEFAULT 0,
    sample_event_ids Array(String),
    metadata String CODEC(ZSTD(3)),
    notes String CODEC(ZSTD(3)),

    -- Indices
    INDEX idx_alert_rule_id rule_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_alert_status status TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_alert_severity severity TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_alert_assignee assignee TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(created_at)
ORDER BY (tenant_id, status, created_at, alert_id)
TTL created_at + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;
