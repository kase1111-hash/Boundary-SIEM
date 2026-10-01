-- Migration: 007_events_insert_deduplication
-- Description: Make retried event inserts idempotent

-- The batch writer sends every INSERT with an insert_deduplication_token and
-- retries a failed INSERT with the same token. A plain MergeTree honours the
-- token only when it keeps a deduplication window, so without this setting an
-- INSERT that the server committed before the client saw an error (a dropped
-- connection, a timeout) was stored twice by the retry.
ALTER TABLE events MODIFY SETTING non_replicated_deduplication_window = 1000;

-- events_critical_mv still pushes a repeated block to events_critical; with
-- deduplicate_blocks_in_dependent_materialized_views (set by the writer) and
-- this window, events_critical drops it as well.
ALTER TABLE events_critical MODIFY SETTING non_replicated_deduplication_window = 1000;
