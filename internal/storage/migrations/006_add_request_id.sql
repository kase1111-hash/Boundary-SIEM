-- Migration: 006_add_request_id
-- Description: Add request_id column to events table for ingest request traceability

ALTER TABLE events ADD COLUMN IF NOT EXISTS request_id String DEFAULT '' AFTER schema_version;

ALTER TABLE events ADD INDEX IF NOT EXISTS idx_request_id request_id TYPE bloom_filter(0.01) GRANULARITY 4;
