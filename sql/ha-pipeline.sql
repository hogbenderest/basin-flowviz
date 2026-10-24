INSERT INTO ha_state_changes_sink
  SELECT event_id, event_type, entity_id, state, ts
  FROM ha_events;

INSERT INTO ha_sensor_readings_sink
  SELECT event_id, entity_id, state, value, unit, ts
  FROM ha_events WHERE event_type = 'sensor';
