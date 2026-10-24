-- flowviz_reports schema (plan 8.2, plus the evidence index the
-- /api/evidence/:id/rows route needs). D1: 10 GB cap, 30-day Time Travel.

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  incident_key TEXT NOT NULL,
  playbook TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  classification TEXT,
  confidence TEXT,
  latest_version INTEGER NOT NULL DEFAULT 1,
  r2_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_seen_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_reports_incident ON reports(incident_key);
CREATE INDEX IF NOT EXISTS idx_reports_updated ON reports(updated_at DESC);

CREATE TABLE IF NOT EXISTS deliveries (
  report_id TEXT NOT NULL,
  report_version INTEGER NOT NULL,
  channel TEXT NOT NULL,
  status TEXT NOT NULL,
  delivered_at TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (report_id, report_version, channel)
);

CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  sql TEXT NOT NULL,
  row_count INTEGER NOT NULL,
  truncated INTEGER NOT NULL DEFAULT 0,
  snapshot_key TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_request ON evidence(request_id);

CREATE TABLE IF NOT EXISTS watermarks (
  detector_id TEXT PRIMARY KEY,
  window_end TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baselines (
  detector_id TEXT NOT NULL,
  bucket TEXT NOT NULL,
  payload TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (detector_id, bucket)
);

CREATE TABLE IF NOT EXISTS drift_flags (
  table_id TEXT PRIMARY KEY,
  ok INTEGER NOT NULL,
  checked_at TEXT NOT NULL,
  detail TEXT
);

CREATE TABLE IF NOT EXISTS scan_budget (
  day TEXT NOT NULL,
  user TEXT NOT NULL,
  bytes_scanned INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, user)
);

CREATE TABLE IF NOT EXISTS ask_rate (
  minute TEXT NOT NULL,
  user TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (minute, user)
);
