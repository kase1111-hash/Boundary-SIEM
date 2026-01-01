-- Migration: 002_create_quarantine
-- Description: Create quarantine table for invalid events

CREATE TABLE IF NOT EXISTS events_quarantine (
    -- Quarantine metadata
    quarantine_id UUID DEFAULT generateUUIDv4(),
    quarantined_at DateTime64(6, 'UTC') DEFAULT now64(6),

    -- Original event data
    raw_event String CODEC(ZSTD(3)),
    source_ip String,
    source_format LowCardinality(String),

    -- Error information
    validation_errors Array(String),
    error_code LowCardinality(String),

    -- Reprocessing tracking
    reprocess_attempts UInt8 DEFAULT 0,
    reprocessed Bool DEFAULT false,
    reprocessed_at Nullable(DateTime64(6, 'UTC')),
    reprocessed_event_id Nullable(UUID)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(quarantined_at)
ORDER BY (quarantined_at, quarantine_id)
TTL quarantined_at + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;
