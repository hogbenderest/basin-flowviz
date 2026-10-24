# basin-flowviz

A faithful replica of the Cloudflare Basin "live data flow" demo for the
ihogben.com account, published at **https://logs.ihogben.com** behind a
Cloudflare Access application (One-Time PIN, explicit allowed email
addresses - the owner plus named colleagues; the audience for an app whose
Access policy IS its authorization model). The
workers.dev URL is dead: Access cannot gate a hostname outside your zone, so
the app lives on a custom domain with `workers_dev: false`.

Five columns: sources -> streams -> pipelines -> Iceberg tables -> query
engines, animated particles on every edge, live event ticker, Bluesky
firehose toggle, and an interactive Basin SQL console with guardrails.

## Layout

```
wrangler.jsonc          Worker config: DOs, stream binding, cron, assets
src/index.ts            Worker: UI, stats, toggle, relay, SSE, SQL proxy
src/jetstream.ts        JetstreamConsumer DO (firehose, toggle, cursor)
src/ticker.ts           TickerHub DO (hibernatable WS hub + ring buffer)
public/                 Vanilla JS/SVG visualization (no build step)
schemas/                Stream schemas (bsky, ha, homelab)
sql/                    Pipeline SQL (fan-out INSERTs)
vector/                 Central + per-Pi Vector configs (LAN ingest)
scripts/setup-basin.sh  One-shot sink/pipeline/secret setup (needs tokens)
docs/DEPLOY.md          Runbook: status, tokens, every remaining step
docs/HA-SETUP.md        HA Pi: Mosquitto addon + mqtt_statestream
```

## Data model

- `bsky_events_stream` -> 5 bsky_* tables (Worker binding, HTTP off)
- `ha_events` -> 2 ha_* tables (Vector over authed HTTP ingest)
- `homelab_events` -> 5 homelab tables (syslog, host_metrics,
  unifi_devices, unifi_clients, dns_queries)
- Logpush (ihogben.com + workers_trace_events) auto-creates 4 more
  stream+sink+pipeline sets into `basin-demo`

Sinks are immutable: schema changes mean delete and recreate the chain.
Account limits: 20 streams/sinks/pipelines; the design lands at 7/16/7.

## Security posture

- Everything browser-facing sits behind Cloudflare Access (OTP, explicit
  allowed email addresses - not email_domain selectors, which would admit
  every mailbox at a whole domain); there is no unauthenticated surface.
  The Vector relay's machine credential passes the gate only via a
  path-scoped Access application for `/relay` (Service Auth); a deny
  policy blocks that token on every other route.
- The response frame is closed: assets ship `X-Frame-Options: DENY` plus
  `frame-ancestors 'none'`, and the DO-cost GET routes send
  `Cross-Origin-Resource-Policy: same-site`.
- The Basin SQL token (R2 Admin R&W) lives only in `.dev.vars` (600) and the
  Worker secret store; never logged, never browser-visible; the console
  proxy is the only consumer. A mandatory pre-token probe tests that Basin
  SQL rejects COPY and multi-statement input (docs/DEPLOY.md).
- SQL console (audit run 1 rewrite): string-aware comment stripping, checks
  run on the same text that is forwarded, single statement only,
  SELECT/SHOW/EXPLAIN/DESCRIBE allowlist, write-keyword blocklist, LIMIT
  above 2000 and OFFSET above 20000 rejected, LIMIT 200 appended when absent,
  10 KB query cap, 30 s abort. Basin SQL's server-side read-only enforcement
  is the backstop.
- POST routes require `application/json` + small bodies; `/relay` caps at
  1 MB and requires the Access service-token headers plus the bearer secret;
  Origin is checked against the serving host.
- Ticker: relay events are timestamp-clamped, size-capped, and
  IPv4/IPv6/MAC-redacted server-side; the Vector-side sanitizer projects a
  safe field set before anything branches to the browser plane; ring entries
  expire after one hour. Syslog/journald/docker message bodies stay
  table-only: the ticker shows entity states and event kinds.
- `logpush = true` ships this Worker's own logs into the workers_trace_events
  table the demo visualizes: never log secrets or raw request bodies.

## LAN plaintext disclosure (accepted risk)

The Vector configs run over the home LAN: MQTT is `mqtt://` (credentials in
plaintext on the LAN) and the UniFi poller disables certificate verification
(self-signed console cert). House DNS telemetry arrives via the router's own
syslog stream (dnsmasq `logqueries`) rather than an HTTP poller: GL.iNet's
AdGuard Home fork keeps its API locked behind their panel (no users, wizard
403s, management over ubus), so queries are read at the dnsmasq layer
upstream of AGH. These are accepted risks for a home network; the documented
upgrades are TLS + cert pinning (`tls.ca_file`). The unauthenticated LAN
listeners (syslog 5517/5515, http_server 8687, vector 8688) are the same
tradeoff every syslog collector makes: any LAN device can inject events.

## Sources

Public (Bluesky) plus own infrastructure only: Home Assistant, server111 and
Pis, UniFi, house DNS resolver, OpenWrt, ihogben.com zone logs, this Worker's
own traces. No customer data.
