# Deploy and operations runbook

Build order, current status, and every remaining step. Commands assume the
repo root (`cd ~/projects/basin-flowviz`) and a wrangler OAuth login
(`npx wrangler login` with `CLOUDFLARE_API_TOKEN` unset, or a token that has
Workers Pipelines + Workers Scripts edit permissions). Deployed URL:
**https://logs.ihogben.com behind a Cloudflare Access application**
(One-Time PIN, allowed email addresses; the relay's service token has its
own path-scoped application - see Access note below).
The workers.dev URL is dead (`workers_dev: false`).

## Status (2026-10-24)

Done and verified live:

- Security gate: Access app `basin-flowviz` (id 0595b445-92f2-4ea6-a48d-525d172b5e5f)
  on logs.ihogben.com, allow policy for explicit email addresses; custom domain
  attached to the Worker; workers.dev disabled. Verified: `curl -I
  https://logs.ihogben.com` returns 302 to the Access login before any Worker
  response; the old URL 404s; POST /relay without a service token 302s to the
  login. The UI, stats, toggle, ticker WS/SSE, and the SQL console are all
  behind Access.
- Audit run 1 fixes deployed (all confirmed findings):
  - SQL console rewritten: string-aware comment stripping, checks and
    forwarded text are the same string, 10 KB query cap, LIMIT > 2000 and
    OFFSET > 20000 rejected, LIMIT 200 appended when absent. 22/23 hunter
    payloads verified rejected/forwarded correctly (harness); OFFSET finding
    was REJECTED by validation as no-security-consequence.
  - JetstreamConsumer: single-flight connect, post-await enabled re-check,
    self-healing alarm, FLUSH_MAX-sized batches, bounded retry buffer with
    drop-newest, validated cursors (both directions), capped row fields.
  - TickerHub: ring TTL (1 h) on read and write, defensive per-event caps.
  - POST routes require Content-Type application/json + small bodies;
    /relay caps at 1 MB; Origin checked against the serving host; toggle
    requires a boolean `enabled` field (no more silent force-off).
  - toTickerEvent: source hardcoded to lan, ts parsed and clamped to
    [now-7d, now+5min] (kills the ring poison and SSE suppression), IPv4/IPv6/MAC
    redaction; the 503 no longer names the missing secret (generic message;
    the UI renders the friendly setup hint client-side).
  - rows(24h) is a server-cached aggregate (`GET /api/rows`, 60 s TTL,
    single-flight): N tabs cost one query set; the client skips polling in
    hidden tabs and backs off after failures.
  - package.json: @cloudflare/workers-types and typescript removed (wrangler
    types generates worker-configuration.d.ts, which is gitignored);
    wrangler pinned to 4.145.0; setup-basin.sh uses the pinned version.
  - .gitignore covers .env.*, *.pem, *.key, credentials.json, .DS_Store.
- Bucket `basin-demo` + Basin Catalog (warehouse
  `48f5cc18f1a716e781d39f1d6777ddc9_basin-demo`); streams bsky_events_stream
  (binding-only, HTTP off), ha_events and homelab_events (HTTP authed).
- Mosquitto broker confirmed running on the HA Pi (core_mosquitto 7.1.2,
  port 1883 open; MQTT integration loaded via hassio).
- server111 recon: Ubuntu 24.04 host (HTPC); UniFi Network Controller runs
  there (owns UDP 5514, so Vector listens on 5517); Docker media stack
  present (docker_logs added as a source, qBittorrent/gluetun excluded from
  the browser ticker by owner-approved default); HA Pi at 192.168.86.109;
  the GL.iNet OpenWrt router is the gateway and LAN DNS.
- Vector installed on server111 (user-level: ~/vector/bin/vector, data dir
  ~/vector-data), configs + secrets at ~/basin-flowviz-vector (see the
  vector env template for the secret keys).

Resolved since (all verified live 2026-10-24):

- Tokens: R2 Admin R&W + Pipelines Send + Access service token all minted
  into .dev.vars (and the server111 secrets file).
- Access: the relay machine credential is scoped by a **second, path-scoped
  self-hosted application** for `logs.ihogben.com/relay` (the only surface
  its Service Auth policy matches). The original app-wide policy was
  converted to decision **deny** for the same service token - machine
  credentials are explicitly blocked on every human surface (probed live:
  token -> /relay 200, token -> /api/sql and /api/stats 302, anonymous 302).
  Access policies cannot be path-scoped within one app - the split is the
  only way to express "service token for /relay only". Lesson learned twice:
  an **Allow** action with a service-token-only selector still demands an
  IdP login (use Service Auth / non_identity), and one app-wide app = one
  audience for every policy on it.
- Access audience: the OTP allow policy is **explicit email addresses**
  (owner + three named colleagues) - not email_domain selectors, which
  would admit every mailbox at the domain (run-2 finding).
- UniFi: the console was migrated to **UniFi OS Server** (port 11443; the
  legacy self-hosted Network Application deb line ended at 10.6 and never
  had the Integration API). Key minted at Settings > Control Plane >
  Integrations > API Keys; endpoints are site-scoped:
  /proxy/network/integration/v1/sites/<siteId>/(devices|clients)?limit=200.
- House DNS: the GL.iNet AdGuard Home fork keeps its HTTP API locked (no
  users configured, wizard 403s, panel manages it over ubus) and writes no
  querylog file. The DNS source is dnsmasq's own query logging
  (`logqueries=1`) shipped via the router's syslog to UDP 5517 - dnsmasq
  sits upstream of AGH and sees every client query; client IPs are hashed
  at ingest. Trade-off: no blocked flag, the chip shows query volume.
- HA Pi: vector-bridge user + mqtt_statestream block live; state changes
  stream to ha_events. MQTT payloads are raw state strings (only numerics
  parse as JSON), so the Vector transform falls back to raw text.
- Vector 0.57+ removed ${VAR} env interpolation: secrets.json (generated
  from vector.env by scripts/make-secrets-json.sh, mode 600) feeds the
  [secret.basin] file backend. crontab @reboot + nohup for first start.
- Verification snapshot (first ~10 minutes): ha.ha_state_changes 982,
  ha.ha_sensor_readings 1218, homelab.syslog 3357, homelab.dns_queries
  387, homelab.unifi_devices/clients 11/11, homelab.host_metrics 22387.

Remaining:

1. **Logpush jobs** (3 zone datasets + workers_trace_events): dashboard flow
   or add Logpush:Edit to an API token (the env token gets 403 even for
   reads).

## Tokens (the manual steps)

Three secrets cannot be minted from this machine with current credentials:

1. **R2 API token, Admin Read & Write** - dashboard: R2 > Overview >
   Account Details > Manage API Tokens > Create Account API token. Add to
   .dev.vars as `BASIN_SQL_TOKEN=<value>`. Scope note: Admin R&W is
   account-wide by design (bucket scoping exists only for Object-level
   permissions). Compensating controls: .dev.vars mode 600, Worker secret
   store only, never logged, revocable in one click.
2. **Basin/Workers Pipelines Send token** - My Profile > API Tokens >
   Create Custom Token with the Pipelines Send permission. Add as
   `BASIN_INGEST_TOKEN=<value>`.
3. **Access service token** - Zero Trust > Service Auth (as above). Add
   `RELAY_CF_ID=` / `RELAY_CF_SECRET=` to both .dev.vars and
   /etc/basin-flowviz/vector.env.

### Mandatory pre-token probe (record the results)

The audit could not verify that Basin SQL rejects the DataFusion COPY verb or
multi-statement input (DataFusion itself executes COPY; the Worker guardrails
now block both shapes at the console, but the endpoint itself must be proven).
After minting the R2 token and BEFORE running setup-basin.sh:

```
export WRANGLER_BASIN_SQL_AUTH_TOKEN=$(grep '^BASIN_SQL_TOKEN=' .dev.vars | cut -d= -f2-)
npx wrangler@4.145.0 basin sql query 48f5cc18f1a716e781d39f1d6777ddc9_basin-demo "COPY (SELECT 1) TO 'x.csv' STORED AS CSV"
npx wrangler@4.145.0 basin sql query 48f5cc18f1a716e781d39f1d6777ddc9_basin-demo "SELECT 1 ; SELECT 2"
```

Both must error. If either executes, STOP and reassess before setting the
Worker secret (the console would then rely on the Worker guardrails alone).

**Result 2026-10-24: both rejected by the service layer** - `40003: only
read-only queries are allowed` and `40003: expected a single SQL statement,
got 2 instead`. The console guardrails are defense-in-depth on top of
verified server-side enforcement.

## Remaining steps in order

### 1. Sinks, pipelines, SQL secret

```
bash scripts/setup-basin.sh
```

Creates 12 sinks + 3 pipelines (homelab syslog INSERT now also routes
event_type docker_log), sets BASIN_SQL_TOKEN on the Worker. Verify (first
flush 3-7 minutes; poll, never assert instantly):

```
export WRANGLER_BASIN_SQL_AUTH_TOKEN=$(grep '^BASIN_SQL_TOKEN=' .dev.vars | cut -d= -f2-)
npx wrangler@4.145.0 basin sql query 48f5cc18f1a716e781d39f1d6777ddc9_basin-demo "SHOW DATABASES"
```

Toggle Bluesky on in the UI (behind Access now), wait 3-7 minutes, then
`SELECT COUNT(*) FROM bsky.bsky_like` should be non-zero. Check silent drops
via the pipelinesUserErrorsAdaptiveGroups GraphQL dataset (pipeline IDs need
dash formatting).

### 2. Logpush jobs (4 total; config-only, immutable after creation)

**As built 2026-10-24** (via the dashboard - the Basin Pipelines destination
has no API surface yet; the flow auto-creates stream + sink + credentials +
pipeline + job):

- Zone (ihogben.com): `http_requests` (pipeline logpush_http_requests_gale),
  `firewall_events` (logpush_firewall_events_surge), `dns_logs`
  (logpush_dns_logs_frost) - all namespace `cfzone`, bucket basin-demo,
  Apache Iceberg. Custom SQL transforms: `sha256("ClientIP") AS "ClientIP"`
  (hash in exact column position, quoted); http_requests additionally drops
  the demo's own relay noise
  (`WHERE NOT ("ClientRequestHost" = 'logs.ihogben.com' AND "ClientRequestURI" = '/relay')`).
- Account: `workers_trace_events` (logpush_workers_trace_events_frost),
  namespace `cfwork`, Simple transform.

Two dashboard-SQL gotchas worth remembering: (1) unquoted mixed-case column
identifiers are lowercased and fail against the mixed-case stream schemas -
quote every column (`"ClientRequestHost"`); (2) the Logpush fields API lists
a superset (gated fields like `FirewallForAI*` are absent from the created
streams) - read the created stream's schema via the pipelines API
(`GET /accounts/{account_id}/pipelines/v1/streams/{stream_id}`) or iterate
off the validator's first missing-column error.

After creation, confirm namespaces with SHOW DATABASES (cfzone/cfwork) and
verify the two Logpush chips (app.js: Worker events by outcome / Zone
requests by status).

### 3. LAN bring-up (as built 2026-10-24)

1. server111: fill ~/basin-flowviz-vector/vector.env (template:
   vector/vector.env.example), generate the secrets file with
   `bash scripts/make-secrets-json.sh` (Vector 0.57+ has no env
   interpolation; the [secret.basin] file backend reads secrets.json,
   mode 600), then
   `~/vector/bin/vector validate ~/basin-flowviz-vector/vector-central.toml`,
   then start: `nohup ~/vector/bin/vector --config ... >> ~/vector-data/vector.log 2>&1 &`
   (the @reboot crontab entry handles reboots). User-level install: no sudo.
   Note: restart cleanly - a draining instance holds the gRPC API port
   (127.0.0.1:8686) for up to 60 s and a fast restart dies on the bind.
2. HA Pi: docs/HA-SETUP.md - vector-bridge user + the mqtt_statestream
   block + restart; validate by watching ha.ha_state_changes grow.
3. GL.iNet router: dnsmasq query logging + remote syslog (SSH as root):
   ```
   uci set dhcp.@dnsmasq[0].logqueries='1'; uci commit dhcp
   /etc/init.d/dnsmasq restart
   uci set system.@system[0].log_ip='192.168.86.111'
   uci set system.@system[0].log_port='5517'; uci commit system
   /etc/init.d/log restart
   ```
   (5514 on server111 belongs to the UniFi controller.) The GL-AXT1800
   hostname matches the is_openwrt check in syslog_rem (prefix "gl").
   AdGuard Home's API is locked by GL.iNet's fork - do not chase it.
4. Other Pis: vector-pi.toml with VECTOR_HOST set per Pi, sink address
   192.168.86.111:8688.
5. UniFi: UniFi OS Server console (port 11443): Settings > Control Plane >
   Integrations > API Keys. Vector sends Accept: application/json (the API
   returns 406 for the x-ndjson default) and skips TLS verification
   (self-signed cert). AP remote-syslog to server111:5517 is optional
   (the controller's own store loses those logs).

### 4. Access audit logs

The plan's Phase 6 audit-log-to-R2 follows the slides-ihogben-com pattern
(the slides-audit-logs bucket exists); revisit the slides skill before
wiring it. The Access app, policy, and gate are live as of 2026-10-24.

## Rehearsal checklist (plan Phase 7)

- Day before: pre-warm every table (toggle Bluesky on for 10 minutes, run
  each chip once). Never cold-start at showtime: first flush 3-7 minutes,
  metrics lag 5-10 minutes.
- Verify toggle behavior: off costs nothing; on resumes inside the bounded
  grace window (60 s) without a replay storm.
- Ticker WebSocket through Access: the UI falls back to /events SSE
  automatically if the upgrade misbehaves; test both paths when logged in.
- Cost hygiene: time-bounded chips; Bluesky off outside demo windows
  (sustained firehose measured ~360 events/s).
- Fallback screenshots for venue Wi-Fi failure.

## Resource budget after full build

| Resource | Count | Limit |
|---|---|---|
| Streams | 7 (3 custom + 3 zone Logpush + 1 workers_trace_events) | 20 |
| Sinks | 16 (5 bsky + 2 ha + 5 homelab + 3 zone + 1 workers_trace_events) | 20 |
| Pipelines | 7 (3 custom + 4 auto) | 20 |

Every future table costs a sink; prefer event_type routing into existing
homelab tables (docker_log already rides the syslog table).
