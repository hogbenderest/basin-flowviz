// Header-stat collectors: table compression (W2, metadata-only via the
// Basin Catalog REST endpoint - zero scans), ingest freshness (W3, one
// bounded UNION probe across all tables), and the cost/day aggregate
// (W3, from recorded scan bytes, AI token usage, and storage growth).
// Everything here runs from the */5 cron behind its own gate; nothing
// runs per-request. The /api/stats handler only reads cached values.
//
// Pricing constants (published pages, read 2026-10-25): Basin SQL
// $0.0025/GB scanned, 10 GB/month included, 10 MB minimum per query;
// Workers AI $0.011 per 1,000 neurons with 10,000 neurons/day free;
// R2 storage $0.015/GB-month. Every displayed figure is an estimate
// and the UI labels it as such.

import { runSqlJson } from "../sql";
import type { ServiceEnv } from "../bindings";
import { catalog } from "../catalog/render";

const SCAN_USD_PER_GB = 0.0025;
const NEURON_USD_PER_K = 0.011;
const FREE_NEURONS_PER_DAY = 10_000;
const R2_USD_PER_GB_MONTH = 0.015;

// Published per-model neuron rates: input and output neurons per
// million tokens (Workers AI pricing table, 2026-10-25). The default
// is the deployment's ASK_MODEL.
const MODEL_NEURONS: Record<string, { inPerM: number; outPerM: number }> = {
  "@cf/meta/llama-3.3-70b-instruct-fp8-fast": { inPerM: 26_668, outPerM: 204_805 },
  "@cf/meta/llama-3.1-70b-instruct-fp8-fast": { inPerM: 26_668, outPerM: 204_805 },
  "@cf/zai-org/glm-5.3-flash": { inPerM: 13_636, outPerM: 45_455 },
  "@cf/zai-org/glm-5.3": { inPerM: 127_273, outPerM: 400_000 },
};
const DEFAULT_NEURONS = MODEL_NEURONS["@cf/meta/llama-3.3-70b-instruct-fp8-fast"];

// Tables expected to flow continuously; only these feed the worst-age
// headline (toggle-dependent or batch sources can idle honestly without
// turning the header red). All tables still appear in perTable.
const CORE_FRESH = new Set([
  "homelab.dns_queries",
  "homelab.syslog",
  "homelab.host_metrics",
  "ha.ha_state_changes",
  "ha.ha_sensor_readings",
  "homelab.unifi_clients",
]);

// ---------------------------------------------------------------------------
// meta helpers (the D1 meta table from migration 0001)
// ---------------------------------------------------------------------------

async function getMeta(env: ServiceEnv, key: string): Promise<unknown | null> {
  if (!env.REPORTS_D1) return null;
  const r = await env.REPORTS_D1.prepare("SELECT value FROM meta WHERE key = ?1")
    .bind(key)
    .first<{ value: string }>();
  if (!r?.value) return null;
  try {
    return JSON.parse(r.value);
  } catch {
    return null;
  }
}

async function setMeta(env: ServiceEnv, key: string, value: unknown): Promise<void> {
  if (!env.REPORTS_D1) return;
  await env.REPORTS_D1.prepare(
    "INSERT INTO meta (key, value, updated_at) VALUES (?1, ?2, ?3) " +
      "ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
  )
    .bind(key, JSON.stringify(value), new Date().toISOString())
    .run()
    .catch(() => {});
}

// Run an action at most once per interval, gated by a meta timestamp.
async function withGate(
  env: ServiceEnv,
  gateKey: string,
  intervalMs: number,
  action: () => Promise<unknown>,
): Promise<void> {
  const last = (await getMeta(env, gateKey)) as { at?: number } | null;
  const at = Number(last?.at ?? 0);
  if (Date.now() - at < intervalMs) return;
  await setMeta(env, gateKey, { at: Date.now() });
  try {
    await action();
  } catch {
    /* next cron tick retries */
  }
}

// ---------------------------------------------------------------------------
// AI usage recording (every model call site reports its usage block)
// ---------------------------------------------------------------------------

export async function recordAiUsage(
  env: ServiceEnv,
  model: string,
  out: unknown,
): Promise<void> {
  if (!env.REPORTS_D1) return;
  const o = (out ?? {}) as Record<string, unknown>;
  const u = o.usage as Record<string, unknown> | undefined;
  const p = Number(u?.prompt_tokens ?? 0);
  const c = Number(u?.completion_tokens ?? 0);
  if ((!Number.isFinite(p) || p === 0) && (!Number.isFinite(c) || c === 0)) return;
  const day = new Date().toISOString().slice(0, 10);
  await env.REPORTS_D1.prepare(
    "INSERT INTO ai_usage (day, model, prompt_tokens, completion_tokens, calls) " +
      "VALUES (?1, ?2, ?3, ?4, 1) " +
      "ON CONFLICT(day, model) DO UPDATE SET prompt_tokens = prompt_tokens + ?3, " +
      "completion_tokens = completion_tokens + ?4, calls = calls + 1",
  )
    .bind(day, model, Number.isFinite(p) ? p : 0, Number.isFinite(c) ? c : 0)
    .run()
    .catch(() => {});
}

// ---------------------------------------------------------------------------
// Ingest freshness: one UNION probe, newest row age per table
// ---------------------------------------------------------------------------

export interface FreshnessSnapshot {
  checkedAt: string;
  perTable: Record<string, number | null>;
  worstAgeSec: number | null;
  worstTable: string | null;
}

function toMs(m: unknown): number | null {
  if (typeof m === "number" && Number.isFinite(m) && m > 0) return m;
  if (typeof m === "string") {
    const t = Date.parse(m);
    if (Number.isFinite(t) && t > 0) return t;
  }
  return null;
}

export async function probeIngestFreshness(env: ServiceEnv): Promise<FreshnessSnapshot> {
  const now = Date.now();
  const checkedAt = new Date(now).toISOString();
  const perTable: Record<string, number | null> = {};
  const arms = catalog.tables.map(
    (t) =>
      `SELECT '${t.id}' AS t, MAX(__ingest_ts) AS m FROM ${t.id} ` +
      `WHERE __ingest_ts >= now() - INTERVAL '1 hour'`,
  );
  // A single statement: one 10 MB minimum billing per probe, not per table.
  const d = await runSqlJson(env, `${arms.join(" UNION ALL ")} LIMIT 100`);
  const rows = (d?.result?.rows ?? []) as { t?: unknown; m?: unknown }[];
  for (const r of rows) {
    const id = String(r?.t ?? "");
    if (!id) continue;
    const ts = toMs(r?.m);
    perTable[id] = ts === null ? null : Math.max(0, Math.round((now - ts) / 1000));
  }
  let worstAgeSec: number | null = null;
  let worstTable: string | null = null;
  for (const [id, age] of Object.entries(perTable)) {
    if (age === null || !CORE_FRESH.has(id)) continue;
    if (worstAgeSec === null || age > worstAgeSec) {
      worstAgeSec = age;
      worstTable = id;
    }
  }
  const snap: FreshnessSnapshot = { checkedAt, perTable, worstAgeSec, worstTable };
  await setMeta(env, "freshness", snap);
  return snap;
}

// ---------------------------------------------------------------------------
// Compression collector (W2): Basin Catalog REST, metadata-only
// ---------------------------------------------------------------------------

interface SnapEntry {
  "snapshot-id"?: number | string;
  "timestamp-ms"?: number;
  summary?: Record<string, string>;
}

export interface CompressionSnapshot {
  updatedAt: string;
  bytesPerRow: number | null;
  bytesPerDay: number | null;
  perTable: Record<
    string,
    { bytesPerRow: number | null; bytesPerDay: number | null; dataFiles: number; checkedAt: string }
  >;
}

export async function collectTableStats(env: ServiceEnv): Promise<CompressionSnapshot | null> {
  if (!env.BASIN_SQL_TOKEN || !env.REPORTS_D1) return null;
  const now = Date.now();
  const checkedAt = new Date(now).toISOString();
  const perTable: CompressionSnapshot["perTable"] = {};
  let sumBytes = 0;
  let sumRows = 0;
  let sumPerDay = 0;

  for (const t of catalog.tables) {
    const dot = t.id.indexOf(".");
    const ns = dot > 0 ? t.id.slice(0, dot) : "";
    const name = dot > 0 ? t.id.slice(dot + 1) : t.id;
    if (!ns) continue;
    try {
      const url =
        `https://api.cloudflare.com/client/v4/accounts/${env.ACCOUNT_ID}` +
        `/r2-catalog/${env.BUCKET}/namespaces/${encodeURIComponent(ns)}` +
        `/tables/${encodeURIComponent(name)}`;
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${env.BASIN_SQL_TOKEN}` },
        signal: AbortSignal.timeout(15_000),
      });
      if (!resp.ok) continue;
      const body = (await resp.json().catch(() => null)) as {
        result?: { metadata?: { snapshots?: SnapEntry[] } };
      } | null;
      const snaps = body?.result?.metadata?.snapshots ?? [];
      if (!snaps.length) continue;
      // Only append commits contribute rows; compaction snapshots carry
      // no added-records and would skew bytes_per_row.
      const appended = snaps.filter((s) => Number(s.summary?.["added-records"] ?? 0) > 0);
      const windowBytes = appended.reduce(
        (a, s) => a + Number(s.summary?.["added-files-size"] ?? 0),
        0,
      );
      const windowRows = appended.reduce(
        (a, s) => a + Number(s.summary?.["added-records"] ?? 0),
        0,
      );
      const tms = appended
        .map((s) => Number(s["timestamp-ms"] ?? 0))
        .filter((n) => Number.isFinite(n) && n > 0);
      const windowMinutes =
        tms.length >= 2 ? (Math.max(...tms) - Math.min(...tms)) / 60_000 : null;
      const newest = snaps[snaps.length - 1];
      const bpr = windowRows > 0 ? windowBytes / windowRows : null;
      const bpd =
        windowMinutes && windowMinutes > 0
          ? windowBytes * (1440 / windowMinutes)
          : null;
      perTable[t.id] = {
        bytesPerRow: bpr,
        bytesPerDay: bpd,
        dataFiles: Number(newest.summary?.["total-data-files"] ?? 0),
        checkedAt,
      };
      sumBytes += windowBytes;
      sumRows += windowRows;
      if (bpd !== null) sumPerDay += bpd;
      await env.REPORTS_D1.prepare(
        "INSERT OR REPLACE INTO table_stats " +
          "(table_id, checked_at, bytes_per_row, window_bytes, window_rows, window_minutes, data_files, snapshot_id) " +
          "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
      )
        .bind(
          t.id,
          checkedAt,
          bpr,
          windowBytes,
          windowRows,
          windowMinutes,
          perTable[t.id].dataFiles,
          String(newest["snapshot-id"] ?? ""),
        )
        .run()
        .catch(() => {});
    } catch {
      /* skip this table this tick; history keeps the last good row */
    }
  }

  if (!Object.keys(perTable).length) return null;
  const snap: CompressionSnapshot = {
    updatedAt: checkedAt,
    bytesPerRow: sumRows > 0 ? sumBytes / sumRows : null,
    bytesPerDay: sumPerDay > 0 ? sumPerDay : null,
    perTable,
  };
  await setMeta(env, "compression", snap);
  // Keep 14 days of per-check history; the aggregates live in meta.
  const cutoff = new Date(now - 14 * 24 * 3600_000).toISOString();
  await env.REPORTS_D1.prepare("DELETE FROM table_stats WHERE checked_at < ?1")
    .bind(cutoff)
    .run()
    .catch(() => {});
  return snap;
}

// ---------------------------------------------------------------------------
// Cost per day (trailing 7-day average of the three cost components)
// ---------------------------------------------------------------------------

export interface CostSnapshot {
  updatedAt: string;
  perDayUsd: number | null;
  breakdown: {
    scan: { usdPerDay: number | null; avgBytesPerDay: number | null };
    ai: { usdPerDay: number | null; avgNeuronsPerDay: number | null };
    storage: { usdPerDay: number | null; bytesPerDay: number | null };
  };
}

function isoDaysAgo(n: number): string {
  return new Date(Date.now() - n * 24 * 3600_000).toISOString().slice(0, 10);
}

export async function computeCostDay(env: ServiceEnv): Promise<CostSnapshot> {
  const updatedAt = new Date().toISOString();
  const since = isoDaysAgo(6);

  // (a) scan cost: daily recorded bytes, trailing 7-day average.
  let scanAvg: number | null = null;
  if (env.REPORTS_D1) {
    const r = await env.REPORTS_D1.prepare(
      "SELECT day, SUM(bytes_scanned) AS b FROM scan_budget WHERE day >= ?1 GROUP BY day",
    )
      .bind(since)
      .all<{ day: string; b: number }>()
      .catch(() => [] as { day: string; b: number }[]);
    const days = (Array.isArray(r) ? r : r.results ?? []) as { b: number }[];
    if (days.length) {
      const total = days.reduce((a, d) => a + Number(d.b ?? 0), 0);
      scanAvg = total / 7; // full-week denominator: quiet days count as zero
    }
  }
  const scanUsd = scanAvg === null ? null : (scanAvg / 1e9) * SCAN_USD_PER_GB;

  // (b) AI cost: tokens per model per day -> neurons -> net of the free
  // daily allocation, trailing 7-day average of the daily net cost.
  let aiAvgNeurons: number | null = null;
  let aiAvgUsd: number | null = null;
  if (env.REPORTS_D1) {
    const r = await env.REPORTS_D1.prepare(
      "SELECT day, model, SUM(prompt_tokens) AS p, SUM(completion_tokens) AS c " +
        "FROM ai_usage WHERE day >= ?1 GROUP BY day, model",
    )
      .bind(since)
      .all<{ day: string; model: string; p: number; c: number }>()
      .catch(() => [] as { day: string; model: string; p: number; c: number }[]);
    const rows = (Array.isArray(r) ? r : r.results ?? []) as { day: string; model: string; p: number; c: number }[];
    if (rows.length) {
      const perDay = new Map<string, number>();
      for (const row of rows) {
        const coef = MODEL_NEURONS[row.model] ?? DEFAULT_NEURONS;
        const neurons =
          (Number(row.p) / 1e6) * coef.inPerM + (Number(row.c) / 1e6) * coef.outPerM;
        perDay.set(row.day, (perDay.get(row.day) ?? 0) + neurons);
      }
      aiAvgNeurons = [...perDay.values()].reduce((a, b) => a + b, 0) / 7;
      // Average of daily net costs (gross minus the free allocation)
      // over the full week.
      let netSum = 0;
      for (const n of perDay.values()) netSum += Math.max(0, n - FREE_NEURONS_PER_DAY);
      aiAvgUsd = (netSum / 7 / 1000) * NEURON_USD_PER_K;
    }
  }

  // (c) storage cost: growth per day from the compression collector,
  // amortized over a 30-day month at R2 rates.
  const comp = (await getMeta(env, "compression")) as CompressionSnapshot | null;
  const bytesPerDay = comp?.bytesPerDay ?? null;
  const storageUsd =
    bytesPerDay === null ? null : (bytesPerDay / 1e9) * 30 * R2_USD_PER_GB_MONTH / 30;

  const parts = [scanUsd, aiAvgUsd, storageUsd].filter((v): v is number => v !== null);
  const perDayUsd = parts.length
    ? parts.reduce((a, b) => a + b, 0)
    : null;
  const snap: CostSnapshot = {
    updatedAt,
    perDayUsd,
    breakdown: {
      scan: { usdPerDay: scanUsd, avgBytesPerDay: scanAvg },
      ai: { usdPerDay: aiAvgUsd, avgNeuronsPerDay: aiAvgNeurons },
      storage: { usdPerDay: storageUsd, bytesPerDay },
    },
  };
  await setMeta(env, "cost_day", snap);
  return snap;
}

// ---------------------------------------------------------------------------
// Cron entrypoint + request-side reader
// ---------------------------------------------------------------------------

export async function runHeaderCollectors(env: ServiceEnv): Promise<void> {
  await withGate(env, "gate_freshness", 15 * 60_000, () => probeIngestFreshness(env));
  await withGate(env, "gate_compression", 60 * 60_000, async () => {
    await collectTableStats(env);
    await computeCostDay(env);
  });
}

export async function getHeaderStats(
  env: ServiceEnv,
): Promise<{
  freshness: FreshnessSnapshot | null;
  cost: CostSnapshot | null;
  compression: CompressionSnapshot | null;
  unread: number | null;
} | null> {
  if (!env.REPORTS_D1) return null;
  const [freshness, cost, compression, unreadRow] = await Promise.all([
    getMeta(env, "freshness"),
    getMeta(env, "cost_day"),
    getMeta(env, "compression"),
    env.REPORTS_D1.prepare("SELECT COUNT(*) AS c FROM reports WHERE status = 'open'")
      .first<{ c: number }>()
      .catch(() => null),
  ]);
  return {
    freshness: (freshness as FreshnessSnapshot | null) ?? null,
    cost: (cost as CostSnapshot | null) ?? null,
    compression: (compression as CompressionSnapshot | null) ?? null,
    unread: unreadRow?.c ?? null,
  };
}
