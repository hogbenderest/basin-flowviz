-- W9: raw (sampled, rows-as-JSON) size per table for the compression
-- percentage headline: stored bytes vs the same rows serialized as JSON.
ALTER TABLE table_stats ADD COLUMN raw_bytes_per_row REAL;
