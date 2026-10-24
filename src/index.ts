// basin-flowviz Worker: serves the visualization UI, the stats endpoints,
// the Bluesky toggle, the LAN relay route, the ticker WebSocket (via TickerHub),
// an SSE fallback, the cached rows-24h stat, the guarded Basin SQL console
// proxy, the Ask service (/api/ask, /api/catalog, /api/evidence), the report
// inbox (/api/investigations), and the investigation scheduler (*/5 cron).
//
// Security posture (audit run 1 fixes, 2026-10-24, unchanged):
// - SQL console: string-aware comment stripping; all checks run on the same
//   analyzed text that is forwarded (no check-vs-send divergence); 10 KB query
//   cap; LIMIT above 2000 and OFFSET above 20000 rejected; LIMIT 200 appended
//   when the analyzed text has none; write keywords and stray semicolons
//   rejected on the analyzed text. Basin SQL's server-side read-only
//   enforcement remains the backstop.
// - POST routes require Content-Type: application/json (blocks CORS
//   simple-request drive-bys), small bodies, and a same-host Origin when an
//   Origin header is present.
// - The Basin SQL token (R2 Admin R&W) lives only in Worker secrets, is never
//   logged or returned, and the missing-token 503 does not name it.
// - `logpush = true` ships console output into cfwork.workers_trace_events:
//   never log secrets, tokens, or raw request bodies.
// - Everything browser-facing sits behind the Cloudflare Access application
//   on logs.ihogben.com; new routes inherit that gate.

import { JetstreamConsumer } from "./jetstream";
import { TickerHub } from "./ticker";
import type { TickerEvent } from "./ticker";
import {
  sanitizeSql,
  runSql,
  MAX_QUERY_CHARS,
} from "./sql";
import type { SqlEnv } from "./sql";
import { handleAsk, handleCatalog, handleEvidenceRows, userOf } from "./ask/handlers";
import { runDetectors, runDriftCheck, type SchedulerEnv } from "./investigate/detectors";

export { JetstreamConsumer, TickerHub };
export { InvestigationWorkflow } from "./investigate/workflow";

interface DONamespace {
  idFromName(name: string): unknown;
  // RPC stubs for the Durable Object classes above.
  get(id: unknown): any;
}

interface Env extends SqlEnv {
  BSKY_STREAM: { send(records: unknown[]): Promise<void> };
  JETSTREAM: DONamespace;
  TICKER: DONamespace;
  RELAY_SECRET?: string;
  ASSETS: FetcherLike;
  AI?: { run(model: string, input: unknown): Promise<unknown> };
  REPORTS_D1?: D1Database;
  REPORTS_R2?: R2Bucket;
  INVESTIGATIONS?: Workflow;
  ASK_MODEL?: string;
  SCAN_BUDGET_MB?: string;
  ASK_PER_MINUTE?: string;
  WEBHOOK_URL?: string;
  WEBHOOK_SECRET?: string;
}

interface FetcherLike {
  fetch(input: RequestInfo, init?: RequestInit): Promise<Response>;
}

interface Ctx {
  waitUntil(p: Promise<unknown>): void;
}

const jet = (env: Env) => env.JETSTREAM.get(env.JETSTREAM.idFromName("singleton"));
const hub = (env: Env) => env.TICKER.get(env.TICKER.idFromName("hub"));

function schedulerEnv(env: Env): SchedulerEnv {
  return env as unknown as SchedulerEnv;
}

// ---------------------------------------------------------------------------
// Request guards
// ---------------------------------------------------------------------------

// POST routes must be JSON and small. application/json forces a CORS
// preflight for cross-origin browsers, killing simple-request drive-bys.
function jsonGuard(req: Request, maxBytes: number): Response | null {
  const ct = (req.headers.get("Content-Type") || "").toLowerCase();
  if (!ct.includes("application/json"))
    return new Response("expected application/json", { status: 415 });
  const cl = Number(req.headers.get("Content-Length") || "0");
  if (cl > maxBytes) return new Response("payload too large", { status: 413 });
  return null;
}

// When a browser Origin is present it must match the serving host. Absent
// Origin (curl, Vector) passes; this is belt-and-braces behind Access.
function originGuard(req: Request): Response | null {
  const origin = req.headers.get("Origin");
  if (!origin) return null;
  try {
    if (new URL(origin).host !== new URL(req.url).host)
      return new Response("cross-origin refused", { status: 403 });
  } catch {
    return new Response("bad origin", { status: 403 });
  }
  return null;
}

// ---------------------------------------------------------------------------
// LAN relay (Vector second sink): ticker feed + live LAN rate counters
// ---------------------------------------------------------------------------

const MAX_RELAY_BYTES = 1024 * 1024;

async function parseRelayBody(req: Request): Promise<any[]> {
  const text = await req.text();
  const out: any[] = [];
  try {
    const j = JSON.parse(text);
    if (Array.isArray(j)) return j;
    if (j && typeof j === "object") return [j];
  } catch {
    /* fall through to ndjson */
  }
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try {
      const j = JSON.parse(t);
      if (Array.isArray(j)) out.push(...j);
      else if (j && typeof j === "object") out.push(j);
    } catch {
      /* skip malformed line */
    }
  }
  return out;
}

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const MAC_RE = /\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b/g;
const IPV6_FULL_RE = /\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b/g;
// Compressed IPv6: any :: token with hex groups around it. The leading
// boundary is captured (re-inserted); the trailing uses a lookahead so the
// boundary character survives the replacement.
const IPV6_COMPRESSED_RE =
  /(^|[^0-9A-Fa-f:])((?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{0,4}::(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4})(?=[^0-9A-Fa-f:]|$)/g;

// Allowlist-style normalization: hardcode the lan source (the caller cannot
// misattribute), validate and clamp the timestamp (kills both the oversized-ts
// ring poison and the future-ts SSE suppression), and redact IPv4/IPv6/MAC as
// defense in depth behind the Vector-side sanitizer.
function toTickerEvent(e: any): TickerEvent {
  const str = (v: unknown): string =>
    typeof v === "string" ? v : v == null ? "" : String(v);
  const kind =
    str(e?.event_type) || str(e?.kind) || str(e?.host) || "event";
  let text = "";
  if (typeof e?.text === "string" && e.text) text = e.text;
  else if (typeof e?.entity_id === "string")
    text = `${e.entity_id} -> ${str(e.state)}`;
  else if (typeof e?.message === "string" && e.message) text = e.message;
  else text = kind;
  text = text
    .replace(IPV4_RE, "[redacted]")
    .replace(MAC_RE, "[redacted]")
    .replace(IPV6_FULL_RE, "[redacted]")
    .replace(IPV6_COMPRESSED_RE, "$1[redacted]")
    .slice(0, 110);
  // Timestamp: parse, sanity-clamp to [now - 7 days, now + 5 min], else now.
  const now = Date.now();
  let t = Date.parse(str(e?.ts) || str(e?.timestamp) || "");
  if (
    !Number.isFinite(t) ||
    t > now + 5 * 60_000 ||
    t < now - 7 * 24 * 3600_000
  ) {
    t = now;
  }
  return {
    source: "lan",
    kind: kind.slice(0, 40),
    text,
    ts: new Date(t).toISOString(),
  };
}

// ---------------------------------------------------------------------------
// SSE fallback for the ticker (in case WebSocket-through-Access misbehaves)
// ---------------------------------------------------------------------------

async function sseResponse(env: Env): Promise<Response> {
  const encoder = new TextEncoder();
  let timer: ReturnType<typeof setInterval> | undefined;
  let closed = false;
  const stream = new ReadableStream({
    async start(controller) {
      let lastTs = 0;
      const send = async () => {
        if (closed) return;
        try {
          const recent: TickerEvent[] = await hub(env).recent();
          const fresh = recent.filter((e) => (Date.parse(e.ts) || 0) > lastTs);
          if (fresh.length) {
            lastTs = Math.max(...fresh.map((e) => Date.parse(e.ts) || 0));
            for (const ev of fresh)
              controller.enqueue(
                encoder.encode(`data: ${JSON.stringify(ev)}\n\n`),
              );
          }
        } catch {
          /* best-effort */
        }
      };
      await send();
      if (!closed) timer = setInterval(send, 2000);
    },
    cancel() {
      closed = true;
      if (timer) clearInterval(timer);
    },
  });
  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}

// ---------------------------------------------------------------------------
// rows(24h) header stat: server-side cached, so N tabs cost one query set
// ---------------------------------------------------------------------------

const ROW_QUERIES = [
  "SELECT COUNT(*) AS c FROM bsky.bsky_post WHERE __ingest_ts >= now() - INTERVAL '1 day'",
  "SELECT COUNT(*) AS c FROM ha.ha_state_changes WHERE __ingest_ts >= now() - INTERVAL '1 day'",
  "SELECT COUNT(*) AS c FROM homelab.syslog WHERE __ingest_ts >= now() - INTERVAL '1 day'",
];
const ROWS_TTL_MS = 60_000;

let rowsCache: { at: number; total: number | null } | null = null;
let rowsInflight: Promise<void> | null = null;

async function computeRows(env: Env): Promise<void> {
  let total = 0;
  let any = false;
  for (const query of ROW_QUERIES) {
    try {
      const resp = await runSql(env, query);
      const d: any = await resp.json();
      if (d?.success && d?.result && Array.isArray(d.result.rows)) {
        total += Number(d.result.rows[0]?.c || 0);
        any = true;
      }
    } catch {
      /* best-effort */
    }
  }
  rowsCache = { at: Date.now(), total: any ? total : null };
}

async function rowsHandler(env: Env): Promise<Response> {
  if (!env.BASIN_SQL_TOKEN)
    return Response.json(
      { rows: null },
      { headers: { "Cache-Control": "no-store" } },
    );
  if (!rowsCache || Date.now() - rowsCache.at >= ROWS_TTL_MS) {
    if (!rowsInflight) {
      rowsInflight = computeRows(env).finally(() => {
        rowsInflight = null;
      });
    }
    await rowsInflight;
  }
  const total = rowsCache ? rowsCache.total : null;
  return Response.json(
    { rows: total },
    { headers: { "Cache-Control": "no-store" } },
  );
}

// ---------------------------------------------------------------------------
// Investigation inbox routes
// ---------------------------------------------------------------------------

async function listInvestigations(env: Env): Promise<Response> {
  if (!env.REPORTS_D1) {
    return Response.json(
      { reports: [], note: "report store not configured" },
      { headers: { "Cache-Control": "no-store" } },
    );
  }
  const { results } = await env.REPORTS_D1.prepare(
    "SELECT id, incident_key, playbook, status, classification, confidence, latest_version, created_at, updated_at " +
      "FROM reports ORDER BY updated_at DESC LIMIT 50",
  ).all<{
    id: string;
    incident_key: string;
    playbook: string;
    status: string;
    classification: string | null;
    confidence: string | null;
    latest_version: number;
    created_at: string;
    updated_at: string;
  }>();
  return Response.json(
    { reports: results ?? [] },
    { headers: { "Cache-Control": "no-store" } },
  );
}

async function getInvestigation(env: Env, id: string): Promise<Response> {
  if (!/^[a-z0-9-_.]{1,64}$/i.test(id) || !env.REPORTS_D1 || !env.REPORTS_R2) {
    return Response.json({ error: "not found" }, { status: 404 });
  }
  const row = await env.REPORTS_D1.prepare(
    "SELECT r2_key, latest_version FROM reports WHERE id = ?1",
  )
    .bind(id)
    .first<{ r2_key: string; latest_version: number }>();
  if (!row) return Response.json({ error: "not found" }, { status: 404 });
  const obj = await env.REPORTS_R2.get(row.r2_key);
  if (!obj) return Response.json({ error: "report body missing" }, { status: 404 });
  const body = await obj.text();
  return new Response(body, {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

async function ackInvestigation(env: Env, id: string, req: Request): Promise<Response> {
  if (!/^[a-z0-9-_.]{1,64}$/i.test(id) || !env.REPORTS_D1) {
    return Response.json({ error: "not found" }, { status: 404 });
  }
  let body: { action?: unknown } = {};
  try {
    body = await req.json();
  } catch {
    /* empty body allowed */
  }
  const status = body.action === "close" ? "closed" : "read";
  await env.REPORTS_D1.prepare("UPDATE reports SET status = ?2 WHERE id = ?1")
    .bind(id, status)
    .run();
  return Response.json({ ok: true, status }, { headers: { "Cache-Control": "no-store" } });
}

// ---------------------------------------------------------------------------
// Scenario route (plan 7.9)
// ---------------------------------------------------------------------------

async function handleScenario(env: Env, req: Request): Promise<Response> {
  let body: { fromUTC?: unknown; toUTC?: unknown; tables?: unknown };
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "invalid JSON body" }, { status: 400 });
  }
  const toMs = typeof body.toUTC === "string" ? Date.parse(body.toUTC) : Date.now();
  const fromMs =
    typeof body.fromUTC === "string"
      ? Date.parse(body.fromUTC)
      : toMs - 2 * 3600_000;
  if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || fromMs >= toMs) {
    return Response.json({ error: "expected {fromUTC, toUTC}" }, { status: 400 });
  }
  if (toMs - fromMs > 6 * 3600_000) {
    return Response.json({ error: "scenario window capped at 6 hours" }, { status: 400 });
  }
  const { assembleScenario } = await import("./investigate/scenario");
  const tables = Array.isArray(body.tables)
    ? (body.tables as unknown[]).map(String).slice(0, 6)
    : undefined;
  const scenario = await assembleScenario(
    env,
    userOf(req),
    { fromUTC: new Date(fromMs).toISOString(), toUTC: new Date(toMs).toISOString() },
    tables,
  );
  return Response.json(scenario, { headers: { "Cache-Control": "no-store" } });
}

// ---------------------------------------------------------------------------
// Worker entry
// ---------------------------------------------------------------------------

export default {
  async fetch(req: Request, env: Env, ctx: Ctx): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    if (path === "/ws") {
      const og = originGuard(req);
      if (og) return og;
      return hub(env).fetch(req);
    }

    if (path === "/events" && req.method === "GET") return sseResponse(env);

    if (path === "/relay" && req.method === "POST") {
      const og = originGuard(req);
      if (og) return og;
      const auth = req.headers.get("Authorization") ?? "";
      if (!env.RELAY_SECRET || auth !== `Bearer ${env.RELAY_SECRET}`) {
        return new Response("unauthorized", { status: 401 });
      }
      const cl = Number(req.headers.get("Content-Length") || "0");
      if (cl > MAX_RELAY_BYTES)
        return new Response("payload too large", { status: 413 });
      const events = await parseRelayBody(req);
      if (events.length) {
        const sample = events.slice(0, 20).map(toTickerEvent);
        await hub(env).push(sample, "lan");
      }
      return Response.json(
        { ok: true, received: events.length },
        { headers: { "Cache-Control": "no-store" } },
      );
    }

    if (path === "/api/stats" && req.method === "GET") {
      const [bsky, ticker] = await Promise.all([
        jet(env).getStats(),
        hub(env).getStats(),
      ]);
      return Response.json(
        { bsky, ticker, ts: Date.now() },
        { headers: { "Cache-Control": "no-store" } },
      );
    }

    if (path === "/api/rows" && req.method === "GET") {
      return rowsHandler(env);
    }

    if (path === "/api/bsky/toggle" && req.method === "POST") {
      const og = originGuard(req);
      if (og) return og;
      const jg = jsonGuard(req, 1024);
      if (jg) return jg;
      const body: any = await req.json().catch(() => null);
      // Absent or non-boolean enabled is a no-op (400), not a forced off.
      if (body === null || typeof body.enabled !== "boolean") {
        return new Response("expected {\"enabled\": boolean}", { status: 400 });
      }
      const state = await jet(env).setEnabled(body.enabled);
      return Response.json(state, {
        headers: { "Cache-Control": "no-store" },
      });
    }

    if (path === "/api/sql" && req.method === "POST") {
      const og = originGuard(req);
      if (og) return og;
      const jg = jsonGuard(req, MAX_QUERY_CHARS + 2048);
      if (jg) return jg;
      if (!env.BASIN_SQL_TOKEN) {
        // Generic message: never announce which secret is missing.
        return Response.json(
          {
            success: false,
            errors: [{ code: 503, message: "Console is not available yet." }],
          },
          { status: 503 },
        );
      }
      const body: any = await req.json().catch(() => ({}));
      const raw = typeof body?.query === "string" ? body.query : "";
      const check = sanitizeSql(raw);
      if (!check.ok) {
        return Response.json(
          { success: false, errors: [{ code: 400, message: check.error }] },
          { status: 400 },
        );
      }
      try {
        return await runSql(env, check.query);
      } catch {
        return Response.json(
          {
            success: false,
            errors: [
              {
                code: 504,
                message: "Query timed out or the SQL endpoint is unreachable.",
              },
            ],
          },
          { status: 504 },
        );
      }
    }

    // ---- Ask service (plan section 5) ----

    if (path === "/api/catalog" && req.method === "GET") {
      return handleCatalog(req);
    }

    if (path === "/api/ask" && req.method === "POST") {
      const og = originGuard(req);
      if (og) return og;
      const jg = jsonGuard(req, 32768);
      if (jg) return jg;
      try {
        return await handleAsk(env, req);
      } catch (e) {
        // Never leak internals; the state machine above covers expected paths.
        return Response.json(
          { state: "failed", notes: ["ask service error"] },
          { status: 500, headers: { "Cache-Control": "no-store" } },
        );
      }
    }

    const evidenceMatch = path.match(/^\/api\/evidence\/([A-Za-z0-9_-]+)\/rows$/);
    if (evidenceMatch && req.method === "GET") {
      return handleEvidenceRows(env, evidenceMatch[1], url);
    }

    if (path === "/api/scenario" && req.method === "POST") {
      const og = originGuard(req);
      if (og) return og;
      const jg = jsonGuard(req, 4096);
      if (jg) return jg;
      try {
        return await handleScenario(env, req);
      } catch {
        return Response.json(
          { error: "scenario service error" },
          { status: 500, headers: { "Cache-Control": "no-store" } },
        );
      }
    }

    // ---- Investigation inbox (plan section 7) ----

    if (path === "/api/investigations" && req.method === "GET") {
      return listInvestigations(env);
    }

    const invMatch = path.match(/^\/api\/investigations\/([A-Za-z0-9-_.]{1,64})$/);
    if (invMatch && req.method === "GET") {
      return getInvestigation(env, invMatch[1], );
    }

    const ackMatch = path.match(/^\/api\/investigations\/([A-Za-z0-9-_.]{1,64})\/ack$/);
    if (ackMatch && req.method === "POST") {
      const og = originGuard(req);
      if (og) return og;
      const jg = jsonGuard(req, 1024);
      if (jg) return jg;
      return ackInvestigation(env, ackMatch[1], req);
    }

    return env.ASSETS.fetch(req);
  },

  // Cron: */2 keeps Jetstream alive (idempotent, toggle-aware, as before).
  // */5 runs the investigation detectors and the once-daily drift check.
  async scheduled(event: unknown, env: Env, ctx: Ctx): Promise<void> {
    const cron = (event as { cron?: string })?.cron ?? "*/2 * * * *";
    if (cron.includes("*/5")) {
      ctx.waitUntil(
        (async () => {
          await runDetectors(schedulerEnv(env)).catch((e) => {
            console.error("detector run failed", e instanceof Error ? e.message : String(e));
          });
          await runDriftCheck(schedulerEnv(env)).catch((e) => {
            console.error("drift check failed", e instanceof Error ? e.message : String(e));
          });
        })(),
      );
      return;
    }
    ctx.waitUntil(jet(env).start());
  },
};
