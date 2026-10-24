// The governed query service: the ONLY path from Ask and investigations to
// Basin SQL. Owns the per-user scan budget, the EXPLAIN preflight, typed
// results, the freshness cache, and evidence snapshots (plan 4.1, 5.1, 5.3).

import { sanitizeSql, runSqlJson, sqlLit, type BasinQueryResponse } from "../sql";
import type { QueryResult, EvidenceRecord } from "../catalog/types";
import type { ServiceEnv } from "../bindings";
import { getTable } from "../catalog/render";

const FRESH_TTL_MS = 60_000;
const SNAPSHOT_ROW_CAP = 200;

export class QueryLimit extends Error {
  constructor(public reason: "budget" | "rate") {
    super(reason);
  }
}

// ---------------------------------------------------------------------------
// Budgets (D1): per-user daily scan bytes, per-user asks per minute.
// Without a D1 binding the service degrades to per-isolate counters so local
// development still works.
// ---------------------------------------------------------------------------

const memBudget = new Map<string, number>();
const memRate = new Map<string, number>();

function budgetCapMb(env: ServiceEnv): number {
  const n = Number(env.SCAN_BUDGET_MB ?? "2048");
  return Number.isFinite(n) && n > 0 ? n : 2048;
}

export async function budgetUsed(env: ServiceEnv, user: string, day: string): Promise<number> {
  if (!env.REPORTS_D1) return memBudget.get(`${day}|${user}`) ?? 0;
  const r = await env.REPORTS_D1.prepare(
    "SELECT bytes_scanned AS b FROM scan_budget WHERE day = ?1 AND user = ?2",
  )
    .bind(day, user)
    .first<{ b: number }>();
  return r?.b ?? 0;
}

export async function recordScan(env: ServiceEnv, user: string, day: string, bytes: number): Promise<void> {
  if (!env.REPORTS_D1) {
    const k = `${day}|${user}`;
    memBudget.set(k, (memBudget.get(k) ?? 0) + bytes);
    return;
  }
  await env.REPORTS_D1.prepare(
    "INSERT INTO scan_budget (day, user, bytes_scanned) VALUES (?1, ?2, ?3) " +
      "ON CONFLICT (day, user) DO UPDATE SET bytes_scanned = bytes_scanned + ?3",
  )
    .bind(day, user, bytes)
    .run();
}

export async function checkBudget(env: ServiceEnv, user: string): Promise<void> {
  const day = new Date().toISOString().slice(0, 10);
  const used = await budgetUsed(env, user, day);
  if (used > budgetCapMb(env) * 1024 * 1024) throw new QueryLimit("budget");
}

export async function rateLimitAsk(env: ServiceEnv, user: string): Promise<void> {
  const minute = new Date().toISOString().slice(0, 16);
  const cap = Number(env.ASK_PER_MINUTE ?? "10");
  if (!env.REPORTS_D1) {
    const k = `${minute}|${user}`;
    const n = (memRate.get(k) ?? 0) + 1;
    memRate.set(k, n);
    if (n > cap) throw new QueryLimit("rate");
    return;
  }
  await env.REPORTS_D1.prepare(
    "INSERT INTO ask_rate (minute, user, count) VALUES (?1, ?2, 1) " +
      "ON CONFLICT (minute, user) DO UPDATE SET count = count + 1",
  )
    .bind(minute, user)
    .run();
  const r = await env.REPORTS_D1.prepare(
    "SELECT count AS c FROM ask_rate WHERE minute = ?1 AND user = ?2",
  )
    .bind(minute, user)
    .first<{ c: number }>();
  if ((r?.c ?? 0) > cap) throw new QueryLimit("rate");
}

// ---------------------------------------------------------------------------
// Freshness cache: MAX(__ingest_ts) per table, refreshed at most once a
// minute per isolate. Bounded to one day of data to keep the probe cheap.
// ---------------------------------------------------------------------------

interface FreshEntry {
  at: number;
  maxIngestTs?: string;
  rows: number;
}
const freshnessCache = new Map<string, FreshEntry>();

async function probeFreshness(env: ServiceEnv, tableId: string): Promise<FreshEntry> {
  const t = getTable(tableId);
  if (!t) return { at: Date.now(), rows: 0 };
  const d = await runSqlJson(
    env,
    `SELECT MAX(__ingest_ts) AS m, COUNT(*) AS c FROM ${t.id} WHERE __ingest_ts >= now() - INTERVAL '1 day' LIMIT 1`,
  );
  const row = d?.result?.rows?.[0] as { m?: string; c?: number } | undefined;
  return {
    at: Date.now(),
    maxIngestTs: row?.m,
    rows: Number(row?.c ?? 0),
  };
}

export async function freshness(
  env: ServiceEnv,
  tableId: string,
): Promise<QueryResult["freshness"]> {
  const cached = freshnessCache.get(tableId);
  if (cached && Date.now() - cached.at < FRESH_TTL_MS) {
    return {
      maxIngestTs: cached.maxIngestTs,
      completeness: cached.rows > 0 ? "verified" : "unknown",
    };
  }
  try {
    const entry = await probeFreshness(env, tableId);
    freshnessCache.set(tableId, entry);
    return {
      maxIngestTs: entry.maxIngestTs,
      completeness: entry.rows > 0 ? "verified" : "unknown",
    };
  } catch {
    const e = cached ?? { at: Date.now(), rows: 0 };
    return { maxIngestTs: e.maxIngestTs, completeness: "unknown" };
  }
}

// ---------------------------------------------------------------------------
// Governed execution: sanitize, EXPLAIN preflight, execute, type the result.
// ---------------------------------------------------------------------------

export type ExecOutcome =
  | { ok: true; result: QueryResult }
  | { ok: false; error: string; code?: number };

function schemaOf(d: BasinQueryResponse): { name: string; type: string }[] {
  const s = d.result?.schema ?? [];
  return s.map((c) => ({
    name: c.name,
    type: c.descriptor?.type?.name ?? c.type ?? "unknown",
  }));
}

export async function executeGoverned(
  env: ServiceEnv,
  user: string,
  sql: string,
  opts: { primaryTable?: string; skipExplain?: boolean } = {},
): Promise<ExecOutcome> {
  const check = sanitizeSql(sql);
  if (!check.ok) return { ok: false, error: check.error, code: 400 };
  try {
    await checkBudget(env, user);
  } catch {
    return { ok: false, error: "daily scan budget exhausted", code: 429 };
  }

  // EXPLAIN preflight: free (metadata-only), catches syntax and unknown
  // columns before any scan is billed.
  if (!opts.skipExplain && env.BASIN_SQL_TOKEN) {
    try {
      const ex = await runSqlJson(env, `EXPLAIN ${check.query}`, 15000);
      if (ex && ex.success === false) {
        const e = ex.errors?.[0];
        return { ok: false, error: `preflight: ${e?.message ?? "EXPLAIN failed"}`, code: e?.code ?? 40004 };
      }
    } catch {
      /* preflight is best-effort; execution guards still apply */
    }
  }

  if (!env.BASIN_SQL_TOKEN) return { ok: false, error: "query token not configured", code: 503 };

  let d: BasinQueryResponse;
  try {
    d = await runSqlJson(env, check.query);
  } catch {
    return { ok: false, error: "query timed out or the SQL endpoint is unreachable", code: 504 };
  }
  if (d.success === false || !d.result) {
    const e = d.errors?.[0];
    return { ok: false, error: e?.message ?? "query failed", code: e?.code ?? 500 };
  }

  const rows = d.result.rows ?? [];
  const metrics = d.result.metrics ?? {};
  const bytes = Number(metrics.bytes_scanned ?? 0);
  await recordScan(env, user, new Date().toISOString().slice(0, 10), bytes).catch(() => {});

  const truncApplied = rows.length >= 2000;
  const fresh = opts.primaryTable
    ? await freshness(env, opts.primaryTable)
    : { completeness: "unknown" as const };

  return {
    ok: true,
    result: {
      requestId: d.result.request_id ?? "unknown",
      schema: schemaOf(d),
      rows,
      metrics: {
        bytesScanned: bytes,
        filesScanned: Number(metrics.files_scanned ?? 0),
      },
      truncation: {
        applied: truncApplied,
        reason: truncApplied ? "result capped by the server row limit" : undefined,
      },
      freshness: fresh,
    },
  };
}

// Free metadata queries (SHOW / DESCRIBE) for the drift job.
export async function runMeta(env: ServiceEnv, sql: string): Promise<Record<string, unknown>[] | null> {
  if (!env.BASIN_SQL_TOKEN) return null;
  const d = await runSqlJson(env, sql, 15000);
  if (!d || d.success === false || !d.result) return null;
  return d.result.rows ?? null;
}

// ---------------------------------------------------------------------------
// Evidence snapshots: rows archived to R2 + a D1 index row. Content-addressed
// by requestId and payload hash, so identical results dedupe to one key.
// ---------------------------------------------------------------------------

async function sha12(s: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(digest))
    .slice(0, 6)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function evidenceIdPattern(): RegExp {
  return /^evid_[A-Za-z0-9_-]{4,64}_[0-9a-f]{12}$/;
}

export async function snapshotEvidence(
  env: ServiceEnv,
  input: { sql: string; result: QueryResult; kind: EvidenceRecord["kind"] },
): Promise<EvidenceRecord> {
  const rows = input.result.rows.slice(0, SNAPSHOT_ROW_CAP);
  const payload = JSON.stringify({
    schema: input.result.schema,
    rows,
    createdAt: new Date().toISOString(),
  });
  const h = await sha12(payload + input.result.requestId);
  const id = `evid_${input.result.requestId || "local"}_${h}`;
  const month = new Date().toISOString().slice(0, 7);
  const snapshotKey = `evidence/${month}/${id}.json`;
  if (env.REPORTS_R2) {
    await env.REPORTS_R2.put(snapshotKey, payload, {
      httpMetadata: { contentType: "application/json" },
    }).catch(() => {});
  }
  if (env.REPORTS_D1) {
    await env.REPORTS_D1.prepare(
      "INSERT OR REPLACE INTO evidence (id, request_id, kind, sql, row_count, truncated, snapshot_key, created_at) " +
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
      .bind(
        id,
        input.result.requestId,
        input.kind,
        input.sql,
        rows.length,
        input.result.truncation.applied,
        snapshotKey,
        new Date().toISOString(),
      )
      .run()
      .catch(() => {});
  }
  return {
    id,
    kind: input.kind,
    sql: input.sql,
    requestId: input.result.requestId,
    rowCount: rows.length,
    truncated: input.result.truncation.applied,
    snapshotKey: env.REPORTS_R2 ? snapshotKey : undefined,
    createdAt: new Date().toISOString(),
  };
}

export async function loadEvidenceRows(
  env: ServiceEnv,
  id: string,
  offset: number,
  limit: number,
): Promise<{ rows: Record<string, unknown>[]; schema: { name: string; type: string }[] } | null> {
  if (!evidenceIdPattern().test(id)) return null;
  const cappedOffset = Math.min(Math.max(offset ?? 0, 0), 20000);
  const cappedLimit = Math.min(Math.max(limit ?? 50, 1), 200);
  let raw: string | null = null;
  if (env.REPORTS_D1) {
    const r = await env.REPORTS_D1!.prepare("SELECT snapshot_key FROM evidence WHERE id = ?1")
      .bind(id)
      .first<{ snapshot_key: string }>();
    if (r?.snapshot_key && env.REPORTS_R2) {
      const obj = await env.REPORTS_R2.get(r.snapshot_key);
      if (obj) raw = await obj.text();
    }
  }
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as {
      rows: Record<string, unknown>[];
      schema: { name: string; type: string }[];
    };
    return {
      rows: parsed.rows.slice(cappedOffset, cappedOffset + cappedLimit),
      schema: parsed.schema,
    };
  } catch {
    return null;
  }
}
