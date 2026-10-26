-- Round 5: persona triage fields on reports + detector state on watermarks.

-- Analyst triage: severity is set by the detector at scan time (escalation
-- rules evaluated there); disposition is a human record and deliberately
-- separate from status (status stays the read/unread/closed flag).
ALTER TABLE reports ADD COLUMN severity TEXT;
ALTER TABLE reports ADD COLUMN mitre_tag TEXT;
ALTER TABLE reports ADD COLUMN disposition TEXT DEFAULT 'unactioned';

-- Backfill: existing reports get a neutral severity; disposition defaults.
UPDATE reports SET severity = 'medium' WHERE severity IS NULL;
UPDATE reports SET disposition = 'unactioned' WHERE disposition IS NULL;

-- Detector state for the coverage card: enabled, last status, last error.
ALTER TABLE watermarks ADD COLUMN enabled INTEGER DEFAULT 1;
ALTER TABLE watermarks ADD COLUMN status TEXT;
ALTER TABLE watermarks ADD COLUMN last_error TEXT;
UPDATE watermarks SET enabled = 1, status = 'active' WHERE status IS NULL;
