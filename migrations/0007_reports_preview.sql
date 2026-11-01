-- Inbox list-row preview (run 8): a one-line entity/metric summary
-- ("client HeleniPhone15 -84 dBm", "AP Kids-U6-Pro ng ch149 78% airtime")
-- so triage does not require opening the report. Built at report assembly
-- in the workflow and refreshed by the scheduler when a repeat detection
-- coalesces into an open report. Nullable: reports written before this
-- column simply render without a preview line.
ALTER TABLE reports ADD COLUMN preview TEXT;
