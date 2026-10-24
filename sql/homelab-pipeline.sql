INSERT INTO homelab_syslog_sink
  SELECT event_id, host, ts, message
  FROM homelab_events
  WHERE event_type = 'syslog' OR event_type = 'openwrt_log' OR event_type = 'docker_log';

INSERT INTO homelab_host_metrics_sink
  SELECT event_id, host, ts, fields
  FROM homelab_events WHERE event_type = 'host_metrics';

INSERT INTO homelab_unifi_devices_sink
  SELECT event_id, ts, fields
  FROM homelab_events WHERE event_type = 'unifi_devices';

INSERT INTO homelab_unifi_clients_sink
  SELECT event_id, ts, fields
  FROM homelab_events WHERE event_type = 'unifi_clients';

INSERT INTO homelab_dns_queries_sink
  SELECT event_id, ts, fields
  FROM homelab_events WHERE event_type = 'dns_queries';
