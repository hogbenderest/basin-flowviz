-- W2 (compression metric) + W3 (AI cost capture) tables.

-- One row per table per collector check. The window_* columns describe
-- the most-recent-snapshots window (added-files-size / added-records
-- over the Basin Catalog REST response); bytes_per_row is the rolling
-- headline. History is pruned to 14 days by the collector itself.
CREATE TABLE IF NOT EXISTS table_stats (
  table_id TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  bytes_per_row REAL,
  window_bytes INTEGER,
  window_rows INTEGER,
  window_minutes REAL,
  data_files INTEGER,
  snapshot_id TEXT,
  PRIMARY KEY (table_id, checked_at)
);
CREATE INDEX IF NOT EXISTS idx_table_stats_latest
  ON table_stats(table_id, checked_at DESC);

-- Accumulated Workers AI token usage per model per day, recorded from
-- the usage block of every model call (planning, narration, synthesis).
CREATE TABLE IF NOT EXISTS ai_usage (
  day TEXT NOT NULL,
  model TEXT NOT NULL,
  prompt_tokens INTEGER NOT NULL DEFAULT 0,
  completion_tokens INTEGER NOT NULL DEFAULT 0,
  calls INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, model)
);
