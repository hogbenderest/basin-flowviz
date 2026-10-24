INSERT INTO bsky_post_sink
  SELECT event_id, did, operation, event_time, created_at, text, langs
  FROM bsky_events_stream WHERE event_type = 'post';

INSERT INTO bsky_like_sink
  SELECT event_id, did, operation, event_time, created_at, subject_uri
  FROM bsky_events_stream WHERE event_type = 'like';

INSERT INTO bsky_repost_sink
  SELECT event_id, did, operation, event_time, created_at, subject_uri
  FROM bsky_events_stream WHERE event_type = 'repost';

INSERT INTO bsky_follow_sink
  SELECT event_id, did, operation, event_time, created_at, subject_did
  FROM bsky_events_stream WHERE event_type = 'follow';

INSERT INTO bsky_block_sink
  SELECT event_id, did, operation, event_time, created_at, subject_did
  FROM bsky_events_stream WHERE event_type = 'block';
