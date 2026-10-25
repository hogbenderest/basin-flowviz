# Ask and Investigations: design notes for operators

This documents the second-generation surface added on top of the flow map:
the Ask bar, the governed query service, and the investigation layer.
Read this file for day-2 operation.

## Surfaces

- **Ask bar** (under the header): free-text questions over the archive.
- **Right panel**: answers, charts, evidence, and the question chip set.
- **Investigations** (header button): the report inbox.
- **SQL console** (unchanged): raw expert access, same guardrails as before.

## How a question becomes an answer

1. `POST /api/ask` (behind the same Cloudflare Access application as
   everything else) receives `{question, session}`. Session state
   (table scope, time window, lineage) is client-held; there is no server
   session store.
2. One Workers AI JSON-mode call (default
   `@cf/meta/llama-3.3-70b-instruct-fp8-fast`, override with the `ASK_MODEL`
   var) produces a typed plan: archetype, table, UTC window, dimensions,
   filters. The model never writes SQL in this MVP: the server compiles SQL
   from the plan deterministically (src/catalog/validate.ts).
3. The compiled SQL passes the same lexical guardrails as the console
   (src/sql.ts), plus a free EXPLAIN preflight, plus the per-user daily scan
   budget (D1 `scan_budget`, default 2048 MB/day, override `SCAN_BUDGET_MB`)
   and a per-minute ask cap (`ASK_PER_MINUTE`, default 10).
4. Answers are computed from query result rows. The model narrates over
   sanitized numbers only; raw log bodies and arrays never reach it.
5. Every answer carries evidence: the SQL, the request id, row counts,
   truncation flags, and an R2-snapshot of up to 200 rows, paged by
   `GET /api/evidence/:id/rows`.

## Catalogue and drift

`src/catalog/catalog.v1.json` is the single source of truth for tables,
columns, JSON paths, caveats, verified questions, and the live platform
facts (double-encoded JSON, the 2000-byte JSON function cap, era-safe
COALESCE extraction, clock drift, the salt/hash discrepancy). The */5 cron
runs a once-daily drift check (SHOW DATABASES + DESCRIBE are free) and
records mismatches in D1 `drift_flags`; gated questions show the reason in
the UI. To change semantics: edit the catalogue, bump `version`, redeploy.

## Investigations

- Detector: `dns-volume` on the */5 cron, watermark-based with 5-minute
  overlap and a 4-minute lag guard (measured steady-state ingest lag is
  1-2 minutes). Trigger: one client exceeding 6x its 7-day hourly baseline
  AND an absolute floor of 150 queries per 10 minutes.
- Bounded Workflow (one Cloudflare Workflows class, `investigation`):
  coverage wait (up to 3 x 90 s), 6 evidence queries, one synthesis model
  call (deterministic template fallback), immutable report to R2
  (`reports/{id}/v{n}.json`), metadata to D1, delivery ledger first.
- Cooldown: same client within 6 hours updates the case instead of
  creating a new investigation. Breaker: more than 5 investigations per
  hour pauses detectors for 2 hours (one note in the inbox).
- Webhook delivery: optional. Set the `WEBHOOK_URL` and `WEBHOOK_SECRET`
   Worker secrets to enable; payload carries classification and counts
   only, never raw evidence. Without them the inbox is the only channel.
- No automated remediation exists anywhere in this system.

## Self-test (the demo)

From a LAN client:

```sh
for i in $(seq 1 400); do dig random$i.flowviz-demo.example.com >/dev/null; done
```

Within about 10 minutes the detector fires, the Workflow runs (1-4 minutes),
and the inbox shows a report with per-minute buckets, top domains, domain
shape, per-client context, a 7-day baseline, and explicit coverage notes.

## Rollback

Everything is additive. Remove the new bindings from `wrangler.jsonc`,
redeploy, and the app reverts to the flow map + console behaviour. The D1
database, R2 bucket, and evidence objects can stay in place (costless) or
be deleted independently.
