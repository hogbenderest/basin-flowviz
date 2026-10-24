// Investigation scheduler glue: the dns-volume detector (playbook 7.2) plus
// the daily catalogue drift check. Runs on the */5 cron. Basin has no row
// triggers or query-result subscriptions, so detection is scheduled,
// watermark-based, and overlapping (plan 7.1). Measured steady-state ingest
// lag is 1-2 minutes; lag_guard is 4 minutes with a coverage re-check inside
// the workflow before evidence gathering.

import { executeGoverned, runMeta } from "../query/service";
import { catalog } from "../catalog/render";
import type { ServiceEnv, WorkflowLike, D1DatabaseLike } from "../bindings";

export interface SchedulerEnv extends ServiceEnv {
  INVESTIGATIONS?: WorkflowLike;
  REPORTS_D1?: D1DatabaseLike;
  WEBHOOK_URL?: string;
  WEBHOOK_SECRET?: string;
}

const LAG_GUARD_MS = 4 * 60_000;
const OVERLAP_MS = 5 * 60_000;
const COOLDOWN_MS = 6 * 3600_000;
const DETECTOR = "dns-volume";
const FLOOR_PER_10MIN = 150;
const MULTIPLIER = 6;
const MAX_PER_HOUR = 5;
const PAUSE_MS = 2 * 3600_000;

async function metaGet(env: SchedulerEnv, key: string): Promise<string | null> {
  if (!env.REPORTS_D1) return null;
  const r = await env.REPORTS_D1.prepare("SELECT value FROM meta WHERE key = ?1")
    .bind(key)
    .first<{ value: string }>();
  return r?.value ?? null;
}

async function metaSet(env: SchedulerEnv, key: string, value: string): Promise<void> {
  if (!env.REPORTS_D1) return;
  await env.REPORTS_D1.prepare(
    "INSERT INTO meta (key, value, updated_at) VALUES (?1, ?2, ?3) " +
      "ON CONFLICT (key) DO UPDATE SET value = ?2, updated_at = ?3",
  )
    .bind(key, value, new Date().toISOString())
    .run();
}

async function refreshBaselines(env: SchedulerEnv): Promise<void> {
  const last = await metaGet(env, "baseline_last_run");
  const now = new Date();
  if (last && now.getTime() - Date.parse(last) < 20 * 3600_000) return;
  // Per-client average hourly volume over 7 days. The subquery stays within
  // the 2000-row cap (clients x hours), the outer aggregate returns one row
  // per client. Era note: the hash scheme changed 2026-10-24T08:42Z; the
  // baseline window includes both eras, which can split one client in two
  // until the boundary ages out of the 7-day window. The floor threshold
  // keeps detection meaningful either way.
  const out = await executeGoverned(
    env,
    "system",
    `SELECT client, ROUND(AVG(hc), 1) AS avg_hourly FROM (` +
      `SELECT COALESCE(json_get_str(fields, 'client_hash'), json_get_str(json_get_str(fields), 'client_hash')) AS client, ` +
      `date_trunc('hour', ts) AS h, COUNT(*) AS hc FROM homelab.dns_queries ` +
      `WHERE __ingest_ts >= now() - INTERVAL '7 day' GROUP BY client, date_trunc('hour', ts)` +
      `) GROUP BY client ORDER BY avg_hourly DESC LIMIT 500`,
    { skipExplain: true },
  );
  if (out.ok) {
    const baseline: Record<string, number> = {};
    for (const r of out.result.rows) {
      const c = String(r.client ?? "");
      if (c) baseline[c] = Number(r.avg_hourly ?? 0);
    }
    if (env.REPORTS_D1) {
      await env.REPORTS_D1.prepare(
        "INSERT INTO baselines (detector_id, bucket, payload, updated_at) VALUES (?1, ?2, ?3, ?4) " +
          "ON CONFLICT (detector_id, bucket) DO UPDATE SET payload = ?3, updated_at = ?4",
      )
        .bind(DETECTOR, "clients", JSON.stringify(baseline), now.toISOString())
        .run();
    }
    await metaSet(env, "baseline_last_run", now.toISOString());
  }
}

async function loadBaseline(env: SchedulerEnv): Promise<Record<string, number>> {
  if (!env.REPORTS_D1) return {};
  const r = await env.REPORTS_D1.prepare(
    "SELECT payload FROM baselines WHERE detector_id = ?1 AND bucket = ?2",
  )
    .bind(DETECTOR, "clients")
    .first<{ payload: string }>();
  if (!r?.payload) return {};
  try {
    return JSON.parse(r.payload) as Record<string, number>;
  } catch {
    return {};
  }
}

async function breakerAllows(env: SchedulerEnv): Promise<boolean> {
  const pausedUntil = await metaGet(env, "detectors_paused_until");
  if (pausedUntil && Date.parse(pausedUntil) > Date.now()) return false;
  if (!env.REPORTS_D1) return true;
  const r = await env.REPORTS_D1.prepare(
    "SELECT COUNT(*) AS c FROM reports WHERE created_at >= ?1",
  )
    .bind(new Date(Date.now() - 3600_000).toISOString())
    .first<{ c: number }>();
  if ((r?.c ?? 0) > MAX_PER_HOUR) {
    await metaSet(env, "detectors_paused_until", new Date(Date.now() + PAUSE_MS).toISOString());
    return false;
  }
  return true;
}

export async function runDetectors(env: SchedulerEnv): Promise<void> {
  if (!env.BASIN_SQL_TOKEN) return;
  await refreshBaselines(env).catch(() => {});
  if (!(await breakerAllows(env))) return;

  const now = Date.now();
  const toMs = now - LAG_GUARD_MS;
  let fromMs = toMs - 10 * 60_000;
  let watermark: string | null = null;
  if (env.REPORTS_D1) {
    const w = await env.REPORTS_D1.prepare("SELECT window_end FROM watermarks WHERE detector_id = ?1")
      .bind(DETECTOR)
      .first<{ window_end: string }>();
    watermark = w?.window_end ?? null;
    if (watermark) {
      const wm = Date.parse(watermark);
      if (Number.isFinite(wm)) fromMs = Math.max(Math.min(fromMs, wm - OVERLAP_MS), toMs - 30 * 60_000);
    }
  }
  if (fromMs >= toMs) {
    if (env.REPORTS_D1) {
      await env.REPORTS_D1.prepare(
        "INSERT INTO watermarks (detector_id, window_end, updated_at) VALUES (?1, ?2, ?3) " +
          "ON CONFLICT (detector_id) DO UPDATE SET window_end = ?2, updated_at = ?3",
      )
        .bind(DETECTOR, new Date(toMs).toISOString(), new Date().toISOString())
        .run();
    }
    return;
  }
  const from = new Date(fromMs).toISOString();
  const to = new Date(toMs).toISOString();

  // Move the watermark before querying so a failure re-scans only the overlap.
  if (env.REPORTS_D1) {
    await env.REPORTS_D1.prepare(
      "INSERT INTO watermarks (detector_id, window_end, updated_at) VALUES (?1, ?2, ?3) " +
        "ON CONFLICT (detector_id) DO UPDATE SET window_end = ?2, updated_at = ?3",
    )
      .bind(DETECTOR, to, new Date().toISOString())
      .run();
  }

  const out = await executeGoverned(
    env,
    "system",
    `SELECT COALESCE(json_get_str(fields, 'client_hash'), json_get_str(json_get_str(fields), 'client_hash')) AS client, ` +
      `COUNT(*) AS c FROM homelab.dns_queries ` +
      `WHERE __ingest_ts >= '${from}' AND __ingest_ts < '${to}' ` +
      `GROUP BY client ORDER BY c DESC LIMIT 200`,
    { primaryTable: "homelab.dns_queries", skipExplain: true },
  );
  if (!out.ok || !env.INVESTIGATIONS) return;

  const baseline = await loadBaseline(env);
  const windowMinutes = (toMs - fromMs) / 60_000;
  const date = to.slice(0, 10);

  for (const row of out.result.rows) {
    const client = String(row.client ?? "");
    const count = Number(row.c ?? 0);
    if (!client) continue;
    const avgHourly = baseline[client] ?? 0;
    const floorScaled = FLOOR_PER_10MIN * (windowMinutes / 10);
    const baselineScaled = avgHourly * MULTIPLIER * (windowMinutes / 60);
    if (count < Math.max(floorScaled, baselineScaled)) continue;

    const key = `dns-volume:${client.slice(0, 10)}:${date}`;
    if (env.REPORTS_D1) {
      const recent = await env.REPORTS_D1.prepare(
        "SELECT id, updated_at FROM reports WHERE incident_key = ?1 ORDER BY updated_at DESC LIMIT 1",
      )
        .bind(key)
        .first<{ id: string; updated_at: string }>();
      if (recent && Date.now() - Date.parse(recent.updated_at) < COOLDOWN_MS) {
        // Coalesced: refresh the case timestamp, do not create a new instance.
        await env.REPORTS_D1.prepare("UPDATE reports SET last_seen_at = ?2, updated_at = ?2 WHERE id = ?1")
          .bind(recent.id, new Date().toISOString())
          .run();
        continue;
      }
    }
    await env.INVESTIGATIONS.create({
      id: `inv-${client.slice(0, 10)}-${Date.now()}`,
      params: {
        detectorId: DETECTOR,
        clientHash: client,
        windowFrom: from,
        windowTo: to,
        candidateCount: count,
        baselineHourly: avgHourly,
        windowMinutes,
        detectedAt: new Date().toISOString(),
      },
    }).catch(() => {});
  }
}

// Daily drift check: compare live schema (DESCRIBE is free) against the
// catalogue and flip flags instead of failing silently (plan 4.1).
export async function runDriftCheck(env: SchedulerEnv): Promise<void> {
  if (!env.BASIN_SQL_TOKEN || !env.REPORTS_D1) return;
  const last = await metaGet(env, "drift_last_run");
  const now = new Date();
  if (last && now.getTime() - Date.parse(last) < 20 * 3600_000) return;

  const dbs = (await runMeta(env, "SHOW DATABASES")) ?? [];
  const namespaces = new Set(dbs.map((r) => String((r as Record<string, unknown>).namespace ?? "")));
  for (const t of catalog.tables) {
    const [ns] = t.id.split(".");
    let ok = true;
    let detail = "";
    if (!namespaces.has(ns)) {
      ok = false;
      detail = `namespace ${ns} missing`;
    } else {
      const cols = (await runMeta(env, `DESCRIBE ${t.id}`)) ?? [];
      const live = new Set(
        cols.map((c) => String((c as Record<string, unknown>).column_name ?? "")),
      );
      const missing = t.columns.map((c) => c.name).filter((c) => !live.has(c));
      if (missing.length) {
        ok = false;
        detail = `missing columns: ${missing.join(", ")}`;
      }
    }
    await env.REPORTS_D1!.prepare(
      "INSERT INTO drift_flags (table_id, ok, checked_at, detail) VALUES (?1, ?2, ?3, ?4) " +
        "ON CONFLICT (table_id) DO UPDATE SET ok = ?2, checked_at = ?3, detail = ?4",
    )
      .bind(t.id, ok ? 1 : 0, now.toISOString(), detail)
      .run();
  }
  await metaSet(env, "drift_last_run", now.toISOString());
}
