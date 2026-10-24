# Home Assistant setup (HA Pi)

The HA Pi contributes one column: state-change events. Home Assistant runs on
the Pi as an appliance, so nothing else is installed on that host; the
Mosquitto addon and one YAML integration do all the work.

## 1. Mosquitto broker: already running

Verified 2026-10-24 via the HA Supervisor API and a port probe: the
`core_mosquitto` addon (v7.1.2) is installed and started, port 1883 is open on
192.168.86.109, and the MQTT integration is loaded (source: hassio, discovery
on). No install step remains. The addon authenticates MQTT clients against
Home Assistant user accounts.

## 2. Create a dedicated MQTT user

1. Settings > People > Users > Add user: `vector-bridge`, strong password,
   Local only, not an administrator.
2. Vector on server111 will authenticate with this user/password
   (`MQTT_USER` / `MQTT_PASSWORD` in the vector env file).

## 3. MQTT integration: already configured

Verified loaded via the addon (no manual step). If you ever rebuild the HA
instance: Settings > Devices & services > Add integration > **MQTT**, host
`core-mosquitto`, port 1883, credentials from step 2.

## 4. Enable mqtt_statestream (YAML-only integration)

Append to `configuration.yaml`:

```yaml
mqtt_statestream:
  base_topic: ha
  publish_attributes: false
  publish_timestamps: false
  include:
    domains:
      - light
      - sensor
      - binary_sensor
      - switch
      - climate
      - media_player
      - input_text
```

Notes:

- The base topic `ha` is load-bearing: Vector's `ha_parse` transform expects
  `ha/{domain}/{entity_id}/state` (4 parts).
- `publish_attributes: false` is deliberate. Attribute topics would carry
  device details and free-form values into the browser ticker plane; state
  topics alone drive the whole demo (state changes, sensor values, lights on).
  This matches the plan's privacy posture.
- The `person` domain is intentionally absent; it only joins after the
  privacy review (plan, Policy compliance).
- Developer tools > YAML > restart Home Assistant (mqtt_statestream cannot be
  reloaded; it needs a restart).

## 5. Validate

1. On server111: `mosquitto_sub -h <ha-pi-ip> -t 'ha/#' -u vector-bridge -P <pw> -C 1`
   - flip a light in HA and watch a `.../state` message arrive.
   - Zero-install alternative: HA Developer tools > MQTT > listen on `ha/#`
     while flipping a light.
2. After Vector is running: check `ticker.lan` climbing at
   https://logs.ihogben.com/api/stats (or the workers.dev URL pre-Phase 6).
3. After the ha_pipeline exists: `SHOW TABLES IN ha`, then
   `SELECT COUNT(*) FROM ha.ha_state_changes WHERE __ingest_ts >= now() - INTERVAL '1 day'`
   in the console. First rows land 3-7 minutes after the first event
   (pipeline warm-up), not instantly.

Validated 2026-10-24: the mqtt_statestream block was appended to
configuration.yaml via the HA config share (backup: configuration.yaml.bak
next to it), HA restarted (the integration has no reload action), and 982+
state-change rows landed in ha.ha_state_changes within minutes. MQTT
payloads are raw state strings ("on", "home", 21.5) - only numerics parse
as JSON, so the Vector ha_parse transform falls back to the raw text.

## 6. Rolling back

Set `mqtt_statestream:` out by commenting the block and restarting, then
uninstall the Mosquitto addon. No other HA surface changes.
