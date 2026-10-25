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
wrangler.jsonc          Worker config: DOs, stream + AI + D1 + R2 + Workflows
                        bindings, assets, two crons (*/2 firehose, */5 detectors)
src/index.ts            Worker: UI, stats, toggle, relay, SSE, SQL proxy,
                        Ask service routes, investigation inbox
src/sql.ts              Shared Basin SQL guardrails (console + Ask + queries)
src/jetstream.ts        JetstreamConsumer DO (firehose, toggle, cursor)
src/ticker.ts           TickerHub DO (hibernatable WS hub + ring buffer)
src/ask/                Ask service: AI planner, handlers, evidence paging
src/query/              Governed query service (shared guardrails + budget)
src/investigate/        Detector scheduler, scenario assembly, Workflow
src/catalog/            Table catalog (single source of truth) + renderers
src/bindings.ts         Shared binding types
migrations/             D1 schema for the report store (flowviz_reports)
public/                 Vanilla JS/SVG visualization + Ask panel (no build)
schemas/                Stream schemas (bsky, ha, homelab)
sql/                    Pipeline SQL (fan-out INSERTs)
vector/                 Central + per-Pi Vector configs (LAN ingest)
scripts/setup-basin.sh  One-shot sink/pipeline/secret setup (needs tokens)
scripts/make-secrets-json.sh  vector.env -> Vector secrets.json (0.57+ has
                        no env interpolation; the file backend is required)
docs/DEPLOY.md          Runbook: status, tokens, every remaining step
docs/HA-SETUP.md        HA Pi: Mosquitto addon + mqtt_statestream
docs/ASK-DESIGN.md      Ask bar, governed queries, investigation layer
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
- SQL guardrails (audit runs 1 and 2): string-aware comment stripping,
  checks run on the same text that is forwarded, single statement only,
  SELECT/SHOW/EXPLAIN/DESCRIBE allowlist, write-keyword blocklist, strict
  LIMIT clause parsing (plain integers only - the MySQL comma form,
  scientific notation and LIMIT ALL are rejected; count capped at 2000,
  OFFSET at 20000; LIMIT 200 appended when absent), 10 KB query cap,
  30 s abort. Basin SQL's server-side read-only enforcement is the
  backstop (probed live: COPY and multi-statement both rejected).
- POST routes require `application/json` and read their bodies through a
  streamed byte cap - never trusting Content-Length, which chunked
  requests do not carry; `/relay` caps at 1 MB and requires the Access
  service-token headers plus the bearer secret; Origin is checked against
  the serving host.
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

## Deploying your own instance

The full runbook with every command, token recipe and gotcha is
`docs/DEPLOY.md` (plus `docs/HA-SETUP.md` and `docs/ASK-DESIGN.md`). This
is the order that works, end to end:

**1. Basin.** Create an R2 bucket and enable the Basin Catalog on it
(`wrangler r2 bucket create <bucket> && wrangler r2 bucket catalog enable
<bucket>`), then edit `wrangler.jsonc` and replace the deployment-specific
values: `ACCOUNT_ID`, `BUCKET`, the `BSKY_STREAM` stream id, the
`REPORTS_D1` database id (create yours in step 3) and the custom-domain
route. Create the three ingest streams from `schemas/`:
`wrangler basin pipelines streams create <name> --schema-file schemas/<file>.json --http-enabled true --http-auth true`.

**2. Tokens.** Copy `.env.example` to `.dev.vars` (never commit it) and
fill in: an R2 API token with Admin Read & Write (`BASIN_SQL_TOKEN`), a
Pipelines Send token (`BASIN_INGEST_TOKEN`), a strong `RELAY_SECRET`, and
the Access service-token pair from step 4 (`RELAY_CF_ID/RELAY_CF_SECRET`).
Run the two mandatory pre-token probes from `docs/DEPLOY.md` (COPY and
multi-statement must both be rejected by Basin SQL) BEFORE wiring the
token into the Worker.

**3. Worker.** `npm install`, then create the supporting infra:
`wrangler d1 create flowviz-reports` (put the id in `wrangler.jsonc`),
`wrangler r2 bucket create flowviz-reports`, `wrangler d1 migrations apply
flowviz-reports --remote`, then `npx wrangler@4.145.0 deploy`. Set the
secrets: `wrangler secret put BASIN_SQL_TOKEN` and `wrangler secret put
RELAY_SECRET` (plus optional `WEBHOOK_URL`/`WEBHOOK_SECRET` for
investigation delivery). Finally run `bash scripts/setup-basin.sh`, which
creates the sinks and pipelines from `sql/` and sets the console secret.

**4. Cloudflare Access (do not skip).** Point a custom domain at the
Worker with `workers_dev: false` (Access cannot gate a workers.dev
hostname). Create the Access application with an OTP policy that lists
**explicit email addresses** - never `email_domain` selectors, which
admit every mailbox at a domain, and this app's Access policy IS its
authorization model. For the Vector relay: create a service token, a
**second, path-scoped Access application** for `<domain>/relay` with a
**Service Auth** (non_identity) policy for that token - a single
app-wide policy lets the machine credential reach every route, including
the SQL console - and add a deny policy for the token on the main app.
See the Access notes in `docs/DEPLOY.md`.

**5. LAN ingest (optional).** Install Vector on a LAN host, copy
`vector/vector.env.example` to `vector.env` with your values, generate
the secrets file (`bash scripts/make-secrets-json.sh` - Vector 0.57+ has
no env interpolation; the `[secret.basin]` file backend is required),
then `vector validate` and start. Sources to wire: Home Assistant
`mqtt_statestream` (`docs/HA-SETUP.md`), the router's syslog with dnsmasq
`logqueries=1` for DNS telemetry (client IPs are hashed with
`CLIENT_SALT` - generate one with `openssl rand -hex 16`), and a UniFi
Integration API key from a UniFi OS Server console. Salt values: a fresh
`CLIENT_SALT` starts a new hash era - hashes are only comparable within
one era.

**6. Logpush (optional).** The Basin Pipelines Logpush destination is
dashboard-only: follow `docs/DEPLOY.md` section 2 for the four jobs
(three zone datasets + `workers_trace_events`). Two gotchas are
documented there: quote every mixed-case column in transform SQL, and
the fields API lists gated fields the created streams do not carry.

**7. Catalog.** `src/catalog/catalog.v1.json` is the single source of
truth for the Ask bar and investigations - tables, columns, caveats and
verified questions. It ships populated for this deployment's tables:
edit it for yours, bump `version`, redeploy. `clientHashIdentities`
ships EMPTY on purpose (it maps client hashes to device names; publishing
such a map undoes the salted-hash privacy control). To label your own
known devices, populate it with hashes computed under YOUR
`CLIENT_SALT` - never publish the populated map. The */5 cron runs a
once-daily drift check against the warehouse and flags mismatches in the
UI; ASK_MODEL, SCAN_BUDGET_MB and ASK_PER_MINUTE tune the Ask service
via `wrangler.jsonc` vars.

**8. Verify.** `SELECT COUNT(*)` on each table after the first roll
(sinks roll every 300 s), flip a light switch and watch
`ha.ha_state_changes` grow, and use the self-test in `docs/ASK-DESIGN.md`
to watch an investigation fire end to end.
