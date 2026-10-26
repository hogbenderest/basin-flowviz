# Populating a Basin: a field guide from a working system

This guide documents every method used to send data into Cloudflare Basin
in this project, with the lessons learned, gotchas discovered, and
authoritative documentation links. It exists so you can build your own
Basin pipeline faster than we did.

## What Basin is

Cloudflare Basin is a serverless data platform that ingests events,
manages Apache Iceberg tables in R2, and queries them with distributed
SQL. The core flow: **events -> stream -> pipeline (SQL transform) ->
sink -> Iceberg table in R2**. Multiple query engines (Basin SQL, DuckDB,
Trino, Snowflake, Spark, PyIceberg) can then read the tables.

- [Basin overview](https://developers.cloudflare.com/basin/)
- [Basin Pipelines](https://developers.cloudflare.com/basin-pipelines/)
- [Basin Catalog](https://developers.cloudflare.com/basin-catalog/)
- [Basin SQL](https://developers.cloudflare.com/basin-sql/)

## The five methods, from simplest to most involved

### Method 1: Direct HTTP POST (no middleware)

The simplest path: POST a JSON event to a Basin ingest stream endpoint.

```
POST https://<stream-id>.ingest.cloudflare.com
Authorization: Bearer <ingest-token>
Content-Type: application/json

{"event_id": "<uuid>", "event_type": "my_event", "my_field": "value", "ts": "2026-10-26T09:00:00Z"}
```

Every event requires a unique `event_id` (a UUID works). The endpoint
accepts a bare JSON object (it wraps it into an array server-side) or
an array of objects.

**What it looks like in this project**: the wifi radio metrics poller on
server111 (`scripts/wifi-poller.py`) polls the UniFi console API every
60 seconds and POSTs one event per wireless client and one per AP radio
directly to the `homelab_events` stream, using the same ingest endpoint
that Vector writes to. No Vector, no middleware: a Python script with
`urllib.request`.

**Gotchas we hit**:
- The ingest endpoint's WAF may reject `python-urllib/3.x` as a user
  agent (403 Forbidden). Send a custom `User-Agent` header.
- Events are at-least-once; `event_id` is required but dedup is not
  guaranteed. Use `approx_distinct(event_id)` where exact counts matter.
- The fields payload should stay under 2000 bytes: the JSON function cap
  in Basin SQL means larger fields cannot use `json_get_*`.

**Docs**: [Basin Pipelines HTTP source](https://developers.cloudflare.com/basin-pipelines/sources/available-sources/http/)

### Method 2: Vector as a relay (the recommended middleware)

[Vector](https://vector.dev/) is the standard approach for most sources:
it normalizes inputs, transforms events with VRL (Vector Remap Language),
and sinks to Basin with batching and retries built in.

**What it looks like in this project**: Vector on server111
(`vector/vector-central.toml`) collects from seven source types,
transforms each with a VRL remap, and sinks to two Basin streams. This
is the primary pipeline for all LAN telemetry.

```
Sources -> Transforms -> Sinks
```

#### Vector sources used in this project

| Source | Config | What it collects |
|--------|--------|------------------|
| `syslog` (UDP/TCP) | ports 514, 601 | router (dnsmasq), OpenWrt, UniFi remote syslog |
| `journald` | systemd journal on server111 | systemd unit logs |
| `docker_logs` | Docker socket | container stdout |
| `host_metrics` | local scrape | CPU, memory, disk IO, network counters |
| `http_client` | UniFi Integration API | device and client snapshots |
| `mqtt` | Home Assistant broker | HA entity state changes |
| `demo_logs` | N/A | demo source (unused) |

**Docs**: [Vector sources](https://vector.dev/docs/reference/configuration/sources/)

#### Vector transforms: the VRL remap

Every source gets a `[transforms.*_rem]` block that normalizes the event
shape into what the Basin pipeline expects:

```toml
[transforms.dns_queries]
type = "remap"
inputs = ["syslog_udp", "syslog_tcp"]
source = '''
m, err = parse_regex(to_string(.message) ?? "", r'query\[(?P<qtype>[^\]]+)\] (?P<domain>\S+) from (?P<client>\S+)$')
if err != null { abort }
. = {
    "event_id": uuid_v4(),
    "event_type": "dns_queries",
    "host": "dns",
    "ts": now(),
    "message": null,
    "fields": { "domain": m.domain, "client_hash": sha2!(m.client + "SECRET[basin.client_salt]"), "query_type": m.qtype }
}
'''
```

Key decisions in this project's transforms:
- **Privacy by design**: DNS client addresses are hashed with a
  per-deployment salt before landing in the warehouse. Syslog lines
  containing dnsmasq queries are aborted (never reach the table) so the
  raw syslog table stays free of per-device DNS metadata.
- **Sampling for the browser ticker**: a separate `relay_sample`
  transform (rate 5) feeds a `relay_sanitize` transform that strips
  message bodies and IPv4/MAC addresses before pushing to the app's
  ticker endpoint. The ticker is deliberately a sanitized plane, never
  evidence.
- **UUID generation**: every event gets `uuid_v4()` at transform time.

**Docs**: [Vector VRL remap transform](https://vector.dev/docs/reference/configuration/transforms/remap/)

#### Vector sinks: Basin HTTP ingest

```toml
[sinks.homelab_basin]
type = "http"
inputs = ["journald_rem", "docker_rem", "syslog_rem", "metrics_rem", "unifi_devices_rem", "unifi_clients_rem", "dns_queries"]
uri = "https://<stream-id>.ingest.cloudflare.com"
encoding.codec = "json"
batch.max_events = 1
batch.timeout_secs = 1
request.headers.Authorization = "Bearer SECRET[basin.basin_ingest_token]"
```

**Gotchas we hit**:
- `batch.max_events = 1` means one POST per event. This is simple but
  chatty. Consider `batch.max_events = 20` with `batch.timeout_secs = 2`
  and `framing.method = "newline_delimited"` for higher throughput.
- Vector 0.57+ requires `SECRET[...]` references for secrets in config
  files. Generate a secrets JSON from your env file with
  `scripts/make-secrets-json.sh`.
- Syslog timestamps can drift (we observed ~7.5 minutes behind on one
  router). Always query by `__ingest_ts` (Basin's ingest timestamp),
  not the event's `ts` column.

**Docs**: [Vector HTTP sink](https://vector.dev/docs/reference/configuration/sinks/http/)

### Method 3: Workers Pipeline binding (direct from a Worker)

A Cloudflare Worker can write to a Basin stream directly through a
Pipeline binding in `wrangler.jsonc`:

```jsonc
"pipelines": [
  {
    "binding": "BSKY_STREAM",
    "stream": "<stream-uuid>"
  }
]
```

Then in the Worker code:

```ts
await env.BSKY_STREAM.send([{ event_id, did, operation, ... }]);
```

**What it looks like in this project**: the Bluesky Jetstream consumer
(a Durable Object inside the same Worker) reads the Bluesky firehose
WebSocket, batches rows, and writes them to the `bsky_events_stream`
through the binding. No HTTP, no token management: the binding handles
auth internally.

**Advantages**: zero external dependencies, no token management, same
Worker runtime as your app. **Limitations**: only works from inside a
Worker; each send call has latency; no transform middleware (the Worker
does the shaping itself).

**Docs**: [Workers Pipeline bindings](https://developers.cloudflare.com/basin-pipelines/get-started/binding-methods/)

### Method 4: Cloudflare Logpush (managed delivery)

Cloudflare products (Zone WAF, HTTP requests, DNS, Workers traces) can
push their logs directly to a Basin stream with zero infrastructure:

```bash
npx wrangler pipelines logpush create --stream <stream-id> \
  --dataset http_requests --dataset-account <account-id>
```

The Logpush pipeline includes a `WHERE` clause and transform SQL applied
at job creation time (e.g., sha256 hashing of client IPs, noise
dropping).

**What it looks like in this project**: four Logpush jobs feed the
`cfzone.*` and `cfwork.*` tables. The zone datasets have their IPs
hashed at the pipeline; the Workers trace dataset ships the Worker's
own console output (which this project uses for its OTel-lite
telemetry).

**Gotchas we hit**:
- Every mixed-case column must be double-quoted in the transform SQL:
  `"ClientIP"` not `ClientIP`. This catches almost everyone.
- The `Logs` field in `workers_trace_events` is an array of structs,
  not a flat string. Extract with
  `array_to_string(Logs, ' ')` then ILIKE + regexp_replace.

**Docs**: [Basin Logpush destination](https://developers.cloudflare.com/basin-pipelines/destinations/)

### Method 5: Self-describing metadata (meta.column_docs)

This project also publishes its semantic catalogue back into the
warehouse as queryable documentation tables. External query engines
(which do not have access to the app's compiled catalogue) can discover
where data lives, what each column means, and how to extract it:

```sql
-- Find out where wifi signal strength lives
SELECT * FROM meta.column_docs
WHERE generation_id = (SELECT MAX(generation_id) FROM meta.column_docs)
  AND description ILIKE '%wifi%signal%'
  OR cross_refs ILIKE '%wifi%signal%';

-- Discover the extraction pattern for a column
SELECT name, extraction_default, extraction_fallback, caveats
FROM meta.column_docs
WHERE parent_id = 'homelab.host_metrics'
  AND generation_id = (SELECT MAX(generation_id) FROM meta.column_docs);

-- Read the platform constraints before writing any query
SELECT * FROM meta.platform_facts
WHERE generation_id = (SELECT MAX(generation_id) FROM meta.platform_facts);
```

The generation script (`scripts/generate-column-docs.py`) compiles
`src/catalog/catalog.v1.json` into these rows. Because Basin Pipelines
is append-only (INSERT, no DELETE), the refresh model uses a
generation_id timestamp: the latest generation is the current truth.

**Docs**: [Basin Pipelines SQL reference](https://developers.cloudflare.com/basin-pipelines/sql-reference/)

## The Basin resource stack

Every data source needs these resources (create once with
`scripts/setup-basin.sh`):

```
Stream (receives events)
  -> Pipeline (SQL: INSERT INTO sink SELECT ... FROM stream WHERE ...)
    -> Sink (r2-data-catalog: writes Iceberg tables to R2)
      -> Table (queryable by Basin SQL and any Iceberg engine)
```

### Creating a new source: the minimal path

```bash
# 1. Create the stream
npx wrangler pipelines stream create my_events

# 2. Create the sink (auto-creates the namespace and table)
npx wrangler pipelines sink create my_sink \
  --type basin-catalog --bucket my-bucket \
  --namespace my_ns --table my_table \
  --catalog-token "$R2_TOKEN"

# 3. Create the pipeline
npx wrangler pipelines pipeline create my_pipeline \
  --sql "INSERT INTO my_sink SELECT * FROM my_events WHERE <condition>"

# 4. Send events to the stream's ingest URI
curl -X POST "https://<stream-id>.ingest.cloudflare.com" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"event_id":"test-1","event_type":"my_event","ts":"2026-10-26T09:00:00Z"}'
```

### Table maintenance: do not skip this

Basin Catalog automatically compacts data files and expires snapshots,
but **only if you store a maintenance credential**. Without it, the
schedule exists but zero maintenance runs ever execute. Every 60-second
ingest roll adds manifest files, and within days multi-table queries die
with error 40020 (5000 Iceberg manifests per query). We measured
9,582 manifests on day 2, 15,186 on day 3. After storing the credential
and enabling snapshot expiration, the failing queries dropped to 226
files.

```bash
# Store the maintenance credential (this is what "credential_status: absent" means)
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$TOKEN\"}" \
  "https://api.cloudflare.com/client/v4/accounts/$ACC/basin-catalog/$BUCKET/credential"

# Enable compaction (128 MB target) and snapshot expiration (7 days, keep 20)
npx wrangler basin catalog compaction enable $BUCKET --target-size 128 --token "$TOKEN"
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_expiration": {"state": "enabled", "min_snapshots_to_keep": 20, "max_snapshot_age": "7d"}}' \
  "https://api.cloudflare.com/client/v4/accounts/$ACC/basin-catalog/$BUCKET/maintenance-configs"
```

Verify: the maintenance-configs endpoint must show
`credential_status: present`, then check a table's `maintenance-runs`
for successful runs.

**Docs**: [Basin Table Maintenance](https://developers.cloudflare.com/basin-catalog/table-maintenance/)

## Querying: the platform you need to know about

### Basin SQL basics

The REST endpoint is `https://api.sql.cloudflarestorage.com/api/v1/accounts/{ACCOUNT_ID}/basin-sql/query/{BUCKET}`
with a Bearer token. It accepts a JSON body `{"query": "<SQL>"}` and
returns `{success, result: {schema, rows, metrics}, errors}`.

```bash
npx wrangler basin sql query "{ACCOUNT_ID}_{BUCKET}" "SELECT * FROM ns.table LIMIT 10"
```

**Docs**: [Basin SQL](https://developers.cloudflare.com/basin-sql/), [pricing](https://developers.cloudflare.com/basin-sql/platform/pricing/)

### The platform constraints (all live-verified in this project)

| Constraint | Value | What happens when you hit it |
|---|---|---|
| JSON function input cap | 2000 bytes | `json_get_str()` returns null silently; use `regexp_replace` on the raw text |
| Manifest cap per query | 5000 Iceberg manifests | Error 40020; batch multi-table queries; keep maintenance credentials valid |
| Per-query billing minimum | 10 MB compressed | Even a query scanning 1 KB bills 10 MB; metadata-only (EXPLAIN, SHOW, DESCRIBE) is free |
| Pipeline commit lag | 1-2 minutes | Fresh events are not immediately queryable; the ticker is real-time, the warehouse is not |
| Default LIMIT | 500 (server) | Basin SQL caps returned rows; the app enforces its own cap of 2000 |
| Mixed-case columns | cfzone, cfwork | `"ClientIP"` not `ClientIP`; always double-quote these |

### The extraction patterns that actually work

Every JSON-typed column has a working extraction pattern, documented in
`meta.column_docs` and the catalogue's `extractionPatterns` section:

**Era-safe COALESCE** (for columns whose encoding changed mid-life):
```sql
COALESCE(json_get_str(fields, 'domain'), json_get_str(json_get_str(fields), 'domain'))
```

**Text-guard + regexp** (for string-wrapped or oversized fields):
```sql
SELECT host AS client,
  ROUND(AVG(TRY_CAST(regexp_replace(
    fields, '^.*"value":(-?[0-9.]+).*$', '$1'
  ) AS DOUBLE)), 1) AS avg_signal_dbm
FROM homelab.host_metrics
WHERE fields ILIKE '%wifi_client%' AND __ingest_ts >= now() - INTERVAL '10 minutes'
GROUP BY host
```

**Array flattening** (for Logpush struct arrays):
```sql
SELECT array_to_string("Logs", ' ') AS flat_logs
FROM cfwork.workers_trace_events
WHERE array_to_string("Logs", ' ') ILIKE '%pattern%'
```

**String-replace counting** (for snapshot arrays too large for JSON functions):
```sql
SELECT ROUND(AVG((LENGTH(fields) - LENGTH(replace(fields, '"type":"WIRELESS"', ''))) / 21.0), 1) AS wireless_count
FROM homelab.unifi_clients
```

## Cost model

This project's actual measured costs (October 2026):

| Component | Cost |
|---|---|
| Warehouse storage (2.2 GB/day growth) | ~$0.03/day |
| Basin SQL scans (detection + answering questions) | ~$0.004/day |
| Workers AI (question planning + investigation synthesis) | effectively $0 (under the 10k neurons/day free tier) |
| Workers runtime (dashboard + API) | effectively $0 (under the free tier) |
| R2 storage + operations | ~$0.02/day |
| **Total** | **~$0.06/day** ($1.80/month) |

The 10 MB per-query minimum is the dominant scan cost: even our
six-detector scan cycle (12 ticks/hour) stays under $0.01/day because
most queries scan far less than the minimum but pay the floor.

**Docs**: [Basin SQL pricing](https://developers.cloudflare.com/basin-sql/platform/pricing/), [R2 pricing](https://developers.cloudflare.com/r2/pricing/)

## The security model

Everything in this project sits behind Cloudflare Access (OTP with an
explicit email allowlist). The demo Worker's custom domain is the only
public surface; the workers.dev URL is disabled. The Vector relay uses
a path-scoped Access service token for `/relay` only, and the service
token is explicitly denied on every human surface (a separate
application with a Service Auth policy).

Data privacy in the warehouse:
- DNS client IPs are salted hashes (per-deployment salt, era-marked).
- The browser ticker is a sanitized plane (message bodies stripped,
  IPs and MACs redacted) and is never used as evidence.
- The catalogue ships with neutral labels; real entity names live in
  a gitignored overlay.
- The repository contains no household identifiers, no secrets, and no
  private paths. `gitleaks` runs on every commit.

## Further reading

- [Basin getting started guide](https://developers.cloudflare.com/basin/get-started/guide/)
- [Basin Catalog: PyIceberg configuration](https://developers.cloudflare.com/basin-catalog/config-examples/pyiceberg/)
- [Basin Catalog: Spark configuration](https://developers.cloudflare.com/basin-catalog/config-examples/spark-python/)
- [Vector VRL language reference](https://vector.dev/docs/reference/vrl/)
- [Vector syslog source](https://vector.dev/docs/reference/configuration/sources/syslog/)
- [Apache Iceberg table spec](https://iceberg.apache.org/spec/)
- [Cloudflare Workers AI pricing](https://developers.cloudflare.com/workers-ai/platform/pricing/)
- [MITRE ATT&CK DNS detection strategies](https://attack.mitre.org/detectionstrategies/DET0400/)
