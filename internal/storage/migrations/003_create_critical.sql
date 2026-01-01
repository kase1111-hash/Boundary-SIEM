-- Migration: 003_create_critical
-- Description: Create table for high-severity events and materialized views

-- Table for high-severity events (faster queries on critical events)
CREATE TABLE IF NOT EXISTS events_critical (
    event_id UUID,
    tenant_id LowCardinality(String),
    timestamp DateTime64(6, 'UTC'),
    source_product LowCardinality(String),
    action LowCardinality(String),
    actor_id String,
    target String,
    severity UInt8,
    raw String CODEC(ZSTD(3))
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp, event_id)
TTL timestamp + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;

-- Materialized view to automatically copy high-severity events
CREATE MATERIALIZED VIEW IF NOT EXISTS events_critical_mv
TO events_critical
AS SELECT
    event_id,
    tenant_id,
    timestamp,
    source_product,
    action,
    actor_id,
    target,
    severity,
    raw
FROM events
WHERE severity >= 8;

-- Materialized view for hourly aggregations (useful for dashboards later)
CREATE MATERIALIZED VIEW IF NOT EXISTS events_hourly_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, source_product, action, outcome, hour)
AS SELECT
    tenant_id,
    source_product,
    action,
    outcome,
    toStartOfHour(timestamp) AS hour,
    count() AS event_count,
    sum(severity) AS severity_sum,
    max(severity) AS severity_max
FROM events
GROUP BY tenant_id, source_product, action, outcome, hour;
