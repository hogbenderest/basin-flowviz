-- Round 6: the triage feedback loop - suppressions with atomic upserts.
-- Scope rules: only entity-scoped detectors are suppressible (dns-volume,
-- ssh-brute-force, host-distress, wifi-degradation); worker-errors and
-- telemetry-blind-spot are close-only (monitor-the-monitor must never be
-- silently suppressible). Pattern keys are detector:entity - never a
-- global date-strip.
CREATE TABLE suppressions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detector_id TEXT NOT NULL,
  pattern_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  triggered_by_report TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  threshold_multiplier INTEGER NOT NULL DEFAULT 2,
  UNIQUE(detector_id, pattern_key)
);
CREATE INDEX idx_suppressions_active ON suppressions(detector_id, pattern_key, expires_at);

-- Inbox lifecycle: find open/read reports faster than a table scan.
CREATE INDEX IF NOT EXISTS idx_reports_status_updated ON reports(status, updated_at DESC);
