-- Migration: 005_improve_search_indices
-- Description: Add token-based indices on action and metadata for better search

-- Token-based index on action for word-level search
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_action_tokens action TYPE tokenbf_v1(16384, 3, 0) GRANULARITY 4;

-- Token-based index on metadata for structured metadata search
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_metadata_tokens metadata TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4;

-- N-gram index on actor_name for substring matching
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_actor_name_ngram actor_name TYPE ngrambf_v1(3, 16384, 3, 0) GRANULARITY 4;

-- N-gram index on target for substring matching
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_target_ngram target TYPE ngrambf_v1(3, 16384, 3, 0) GRANULARITY 4;
