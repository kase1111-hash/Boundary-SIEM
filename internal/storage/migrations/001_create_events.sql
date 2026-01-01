-- Migration: 001_create_events
-- Description: Create main events table with time-based partitioning

CREATE TABLE IF NOT EXISTS events (
    -- Primary identifiers
    event_id UUID,
    tenant_id LowCardinality(String),

    -- Timestamps
    timestamp DateTime64(6, 'UTC'),
    received_at DateTime64(6, 'UTC') DEFAULT now64(6),

    -- Source information
    source_product LowCardinality(String),
    source_host String,
    source_instance_id String,
    source_version LowCardinality(String),

    -- Actor information
    actor_type LowCardinality(String),
    actor_id String,
    actor_name String,
    actor_email String,
    actor_ip String,

    -- Event details
    action LowCardinality(String),
    target String,
    outcome LowCardinality(String),
    severity UInt8,

    -- Schema metadata
    schema_version LowCardinality(String),

    -- Raw and metadata (compressed)
    raw String CODEC(ZSTD(3)),
    metadata String CODEC(ZSTD(3)),

    -- Bloom filter indices for fast lookups
    INDEX idx_action action TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_actor_id actor_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_target target TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_source_host source_host TYPE bloom_filter(0.01) GRANULARITY 4,

    -- Token-based full-text index on raw
    INDEX idx_raw_tokens raw TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, source_product, toStartOfHour(timestamp), event_id)
TTL timestamp + INTERVAL 90 DAY DELETE
SETTINGS
    index_granularity = 8192,
    ttl_only_drop_parts = 1;
