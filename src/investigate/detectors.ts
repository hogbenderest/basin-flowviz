// Investigation scheduler glue (round 5: persona-grounded detectors).
// Basin has no row triggers or query-result subscriptions, so detection is
// scheduled, watermark-based, and overlapping (plan 7.1). Measured pipeline
// commit lag is 1-2 minutes; every scan window is lag-guarded with overlap.
//
// Architecture (run-5 challenger amendments): a DETECTORS registry where
// each entry owns its scan, cadence, cooldown and breaker (a noisy
// detector can never starve the others), per-detector watermarks, and a
// shared syslog-overview pass feeding the syslog-based detectors with
// ONE data query per tick. Evidence rules: aggregates only - raw message
// bodies never reach the model. The blind-spot detector reads the
// freshness meta snapshot and never queries Basin. Cost: each data scan
// bills the 10 MB minimum, so scan cadences are tuned per detector.

import { executeGoverned, runMeta } from "../query/service";
import { catalog } from "../catalog/render";
import { sqlLit } from "../sql";
import { buildPreview } from "./preview";
import type { ServiceEnv, WorkflowLike, D1DatabaseLike } from "../bindings";

export interface SchedulerEnv extends ServiceEnv {
  INVESTIGATIONS?: WorkflowLike;
  REPORTS_D1?: D1DatabaseLike;
  WEBHOOK_URL?: string;
  WEBHOOK_SECRET?: string;
}

const LAG_GUARD_MS = 4 * 60_000;
const OVERLAP_MS = 5 * 60_000;
const COVERAGE_MARGIN_MS = 90_000;

// ---------------------------------------------------------------------------
// meta helpers
// ---------------------------------------------------------------------------

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
      "ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
  )
    .bind(key, value, new Date().toISOString())
    .run();
}

async function metaGetJson(env: SchedulerEnv, key: string): Promise<Record<string, unknown> | null> {
  const raw = await metaGet(env, key);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// detector registry
// ---------------------------------------------------------------------------

export interface Candidate {
  // Stable incident key: repeated detections coalesce into one report.
  key: string;
  severity: "critical" | "high" | "medium" | "low";
  // Aggregate-only context carried into the workflow (never raw messages).
  candidate: Record<string, unknown>;
}

export interface DetectorDef {
  id: string;
  mitreTag: string | null;
  primaryTable: string | null; // null: meta-driven, no Basin query
  intervalMs: number; // minimum spacing between scans
  cooldownMs: number; // report coalescing window per incident key
  maxPerHour: number; // per-detector breaker
  pausedMs: number; // breaker pause duration
  severity: Candidate["severity"];
  enabled: boolean; // gated detectors document themselves on the card
  gatedNote?: string;
  // Round 6: only entity-scoped patterns are suppressible. The
  // monitor-the-monitor and whole-app detectors are close-only.
  suppressible: boolean;
  scan: (env: SchedulerEnv, from: string, to: string) => Promise<Candidate[]>;
}

// Pattern key extraction: the stable entity part of an incident key.
// Entity-scoped keys look like `detector:entity:YYYY-MM-DD` - the pattern
// is `detector:entity`. Non-suppressible detectors return null.
export function patternKey(incidentKey: string, detectorId: string): string | null {
  const parts = incidentKey.split(":");
  // Expected: [detectorId, entity, date] or [detectorId, entity]
  if (parts.length < 2) return null;
  const entity = parts.slice(1, -1).join(":") || parts[1];
  if (!entity || entity.match(/^\d{4}-\d{2}-\d{2}/)) return null;
  return `${detectorId}:${entity}`;
}

// Active suppressions for a set of candidate keys (one batched D1 read
// per detector per tick, not N+1 per candidate).
export interface ActiveSuppression {
  pattern_key: string;
  count: number;
  threshold_multiplier: number;
}

export async function fetchSuppressions(
  env: SchedulerEnv,
  detectorId: string,
  candidateKeys: string[],
): Promise<Map<string, ActiveSuppression>> {
  const map = new Map<string, ActiveSuppression>();
  if (!env.REPORTS_D1 || candidateKeys.length === 0) return map;
  const patterns = candidateKeys
    .map((k) => patternKey(k, detectorId))
    .filter((k): k is string => k !== null);
  if (patterns.length === 0) return map;
  const placeholders = patterns.map((_, i) => `?${i + 2}`).join(", ");
  const r = await env.REPORTS_D1.prepare(
    `SELECT pattern_key, count, threshold_multiplier FROM suppressions ` +
      `WHERE detector_id = ?1 AND pattern_key IN (${placeholders}) AND expires_at > ?${patterns.length + 2}`,
  )
    .bind(detectorId, ...patterns, new Date().toISOString())
    .all<{ pattern_key: string; count: number; threshold_multiplier: number }>();
  for (const row of (Array.isArray(r) ? r : r.results ?? [])) {
    map.set(row.pattern_key, row);
  }
  return map;
}

// Era-safe extraction for dns_queries (encoding changed mid-day 2026-10-24).
const DNS_CLIENT = `COALESCE(json_get_str(fields, 'client_hash'), json_get_str(json_get_str(fields), 'client_hash'))`;
const DNS_DOMAIN = `COALESCE(json_get_str(fields, 'domain'), json_get_str(json_get_str(fields), 'domain'))`;

// ssh-brute-force / host-distress share ONE overview query per tick.
// Aggregates only: pattern counts per host, never message text.
async function syslogOverview(env: SchedulerEnv, from: string, to: string): Promise<Record<string, unknown>[]> {
  const out = await executeGoverned(
    env,
    "system",
    `SELECT host, ` +
      `SUM(CASE WHEN message ILIKE '%failed password%' OR message ILIKE '%invalid user%' THEN 1 ELSE 0 END) AS auth_fail, ` +
      `SUM(CASE WHEN message ILIKE '%accepted password%' OR message ILIKE '%accepted publickey%' THEN 1 ELSE 0 END) AS auth_ok, ` +
      `SUM(CASE WHEN message ILIKE '%out of memory%' OR message ILIKE '%killed process%' THEN 1 ELSE 0 END) AS oom, ` +
      `SUM(CASE WHEN message ILIKE '%main process exited%' OR message ILIKE '%failed to start%' OR message ILIKE '%scheduled restart%' THEN 1 ELSE 0 END) AS distress, ` +
      `COUNT(*) AS total ` +
      `FROM homelab.syslog WHERE __ingest_ts >= '${from}' AND __ingest_ts < '${to}' ` +
      `GROUP BY host LIMIT 200`,
    { primaryTable: "homelab.syslog", skipExplain: true },
  );
  if (!out.ok) return [];
  return out.result.rows as Record<string, unknown>[];
}

// Wifi signal extraction (W1 live-verified pattern: ILIKE guard +
// regexp + TRY_CAST on the string-wrapped wifi rows).
const WIFI_SIG = `TRY_CAST(regexp_replace(fields, '^.*"value":(-?[0-9.]+).*$', '$1') AS DOUBLE)`;

// Wifi tag extraction (live-verified 2026-11-01 on both row types):
// numeric tags with the capture-group value pattern; string tags with a
// quoted capture group. Every use is guarded by a fields ILIKE row
// filter; the CASE WHEN keeps a missing tag NULL instead of letting
// regexp_replace fall through to the whole fields string.
const WIFI_NUM = (k: string) =>
  `TRY_CAST(regexp_replace(fields, '^.*"${k}":(-?[0-9.]+).*$', '$1') AS DOUBLE)`;
const WIFI_STR = (k: string) =>
  `CASE WHEN fields ILIKE '%"${k}":"%' THEN substr(regexp_replace(fields, '^.*"${k}":"([^"]+)".*$', '$1'), 1, 40) ELSE NULL END`;

// Per-tick memo for the shared overview scan (per isolate, per run).
let overviewCache: { at: number; from: string; to: string; rows: Record<string, unknown>[] } | null = null;
async function overviewMemo(env: SchedulerEnv, from: string, to: string) {
  if (!overviewCache || overviewCache.from !== from || overviewCache.to !== to) {
    overviewCache = { at: Date.now(), from, to, rows: await syslogOverview(env, from, to) };
  }
  return overviewCache.rows;
}

// ---------------------------------------------------------------------------
// baselines (dns-volume: per-client hourly average, 20h refresh)
// ---------------------------------------------------------------------------

async function refreshBaselines(env: SchedulerEnv): Promise<void> {
  const last = await metaGet(env, "baseline_last_run");
  const now = new Date();
  if (last && now.getTime() - Date.parse(last) < 20 * 3600_000) return;
  const out = await executeGoverned(
    env,
    "system",
    `SELECT client, ROUND(AVG(hc), 1) AS avg_hourly FROM (` +
      `SELECT ${DNS_CLIENT} AS client, date_trunc('hour', ts) AS h, COUNT(*) AS hc ` +
      `FROM homelab.dns_queries WHERE __ingest_ts >= now() - INTERVAL '7 day' ` +
      `GROUP BY client, date_trunc('hour', ts)) GROUP BY client ORDER BY avg_hourly DESC LIMIT 500`,
    { skipExplain: true },
  );
  if (out.ok && env.REPORTS_D1) {
    const baseline: Record<string, number> = {};
    for (const r of out.result.rows) {
      const c = String((r as Record<string, unknown>).client ?? "");
      if (c) baseline[c] = Number((r as Record<string, unknown>).avg_hourly ?? 0);
    }
    await env.REPORTS_D1.prepare(
      "INSERT INTO baselines (detector_id, bucket, payload, updated_at) VALUES (?1, ?2, ?3, ?4) " +
        "ON CONFLICT(detector_id, bucket) DO UPDATE SET payload = ?3, updated_at = ?4",
    )
      .bind("dns-volume", "clients", JSON.stringify(baseline), now.toISOString())
      .run();
    await metaSet(env, "baseline_last_run", now.toISOString());
  }
}

async function loadBaseline(env: SchedulerEnv): Promise<Record<string, number>> {
  if (!env.REPORTS_D1) return {};
  const r = await env.REPORTS_D1.prepare(
    "SELECT payload FROM baselines WHERE detector_id = ?1 AND bucket = ?2",
  )
    .bind("dns-volume", "clients")
    .first<{ payload: string }>();
  if (!r?.payload) return {};
  try {
    return JSON.parse(r.payload) as Record<string, number>;
  } catch {
    return {};
  }
}

// ---------------------------------------------------------------------------
// the registry
// ---------------------------------------------------------------------------

const SSH_FLOOR_PER_10MIN = 10; // 7-day live distribution: ~2 failures/week total
const SSH_ESCALATE_MIN_FAILS = 5; // accepted-after-failures correlation floor
const DISTRESS_LOOP_COUNT = 3; // restart-loop shape within the window
const WORKER_ERROR_BURST = 25; // canceled+unknown baseline ~50/day
const WIFI_SIG_FLOOR_DBM = -83; // live medians run -79.6..-68.7
const WIFI_AP_CU_FLOOR = 70; // observed normal peak 33%
// Congestion corroborators (challenger: retries_pct alone fires on a
// normal day here - LivingRoom runs 19.6% at 27.7% cu - so cu is the
// primary signal and each corroborator must clear a wide bar).
const WIFI_CONGESTION_CU_FLOOR = 70; // airtime saturation
const WIFI_CONGESTION_MIN_SAMPLES = 10;
const WIFI_CONGESTION_SAT_FLOOR = 70; // per-client satisfaction score, %
const WIFI_CONGESTION_STA_FLOOR = 25; // stations on one radio
const WIFI_CONGESTION_RETRY_PCT = 30; // tx retry percentage
// WAN lease heartbeat (3-day live cadence: 4 renewals/hour, no gaps).
// ~2.5 missed renewals at 40 minutes; router-quiet shares the threshold
// because the renewals themselves prove liveness when the router logs
// nothing else.
const WAN_HEARTBEAT_MAX_AGE_MS = 40 * 60_000;
const WAN_ROUTER_QUIET_MS = 40 * 60_000;
const WAN_LOOKBACK = "2 hours";
const BLINDSPOT_TABLE_AGE_MS = 20 * 60_000; // freshness cadence + commit lag
const BLINDSPOT_VECTOR_AGE_MS = 10 * 60_000;

const EXPECTED_FLOWING = new Set([
  "homelab.dns_queries",
  "homelab.syslog",
  "homelab.host_metrics",
  "ha.ha_state_changes",
  "ha.ha_sensor_readings",
  "homelab.unifi_clients",
]);

// ---------------------------------------------------------------------------
// pure verdict helpers (exported for vitest; live-verified thresholds)
// ---------------------------------------------------------------------------

// WAN heartbeat verdict from observed ages. Contract:
//   - renewals stale (>40m) AND router still logging -> heartbeat (high):
//     the DHCP-level WAN link dropped while the syslog path is proven alive.
//   - renewals stale AND router fully quiet -> router-silent (low): the
//     router stopped logging entirely, so WAN state is unknowable here.
//   - renewals fresh -> no connectivity verdict (renewals prove liveness
//     even when the router otherwise stays quiet).
// ip-change is independent and always evaluated.
export interface WanVerdict {
  scope: "heartbeat" | "router-silent" | "ip-change";
  severity: "high" | "low";
  context: Record<string, unknown>;
}

export function wanVerdicts(
  nowMs: number,
  lastWanMs: number | null,
  lastAnyMs: number | null,
  wanIp: string,
  prevIp: string | null,
): WanVerdict[] {
  const out: WanVerdict[] = [];
  const wanStaleMin =
    lastWanMs === null ? null : Math.max(0, Math.round((nowMs - lastWanMs) / 60_000));
  const routerQuietMin =
    lastAnyMs === null ? null : Math.max(0, Math.round((nowMs - lastAnyMs) / 60_000));
  const wanOk = wanStaleMin !== null && wanStaleMin <= WAN_HEARTBEAT_MAX_AGE_MS / 60_000;
  const routerOk = routerQuietMin !== null && routerQuietMin <= WAN_ROUTER_QUIET_MS / 60_000;
  if (!wanOk && routerOk) {
    out.push({
      scope: "heartbeat",
      severity: "high",
      context: { wanStaleMin, routerQuietMin, wanIp },
    });
  } else if (!wanOk && !routerOk) {
    out.push({
      scope: "router-silent",
      severity: "low",
      context: { routerQuietMin, wanStaleMin, wanIp },
    });
  }
  if (wanIp && prevIp && wanIp !== prevIp) {
    out.push({
      scope: "ip-change",
      severity: "low",
      context: { previousIp: prevIp, wanIp },
    });
  }
  return out;
}

// Congestion firing rule: airtime saturation is the primary signal; the
// corroborators (client satisfaction, station count, retry percentage)
// must clear wide bars because retries alone run ~20% on a normal day.
export function congestionFires(
  avgCu: number,
  avgSat: number,
  avgSta: number,
  avgRetryPct: number,
  samples: number,
): boolean {
  if (avgCu <= WIFI_CONGESTION_CU_FLOOR) return false;
  if (samples < WIFI_CONGESTION_MIN_SAMPLES) return false;
  return (
    avgSat < WIFI_CONGESTION_SAT_FLOOR ||
    avgSta >= WIFI_CONGESTION_STA_FLOOR ||
    avgRetryPct > WIFI_CONGESTION_RETRY_PCT
  );
}

export const BLIND_SPOTS: string[] = [
  "No NetFlow: non-DNS data-volume exfiltration is invisible",
  "No endpoint process telemetry: application-level detections are out of reach",
  "No Windows/AD: logon analytics do not exist",
  "DNS label entropy needs Worker-side computation (planned, tier 2)",
  "Presence detection is a phones-on-wifi heuristic, not truth",
  "No certificate or DNS-registrar telemetry",
  "Client identities are salted hashes: labelling is local-only by design",
  "No filesystem utilization metric in Vector's host_metrics: disk-exhaustion projection is gated",
];

export const DETECTORS: DetectorDef[] = [
  {
    id: "dns-volume",
    mitreTag: "T1048",
    primaryTable: "homelab.dns_queries",
    intervalMs: 0,
    cooldownMs: 6 * 3600_000,
    maxPerHour: 5,
    pausedMs: 2 * 3600_000,
    severity: "high",
    enabled: true,
    suppressible: true,
    scan: async (env, from, to) => {
      // Verbatim from the shipped single-detector build (playbook 7.2).
      const out = await executeGoverned(
        env,
        "system",
        `SELECT ${DNS_CLIENT} AS client, COUNT(*) AS c FROM homelab.dns_queries ` +
          `WHERE __ingest_ts >= '${from}' AND __ingest_ts < '${to}' ` +
          `GROUP BY client ORDER BY c DESC LIMIT 200`,
        { primaryTable: "homelab.dns_queries", skipExplain: true },
      );
      if (!out.ok) return [];
      const baseline = await loadBaseline(env);
      const fromMs = Date.parse(from);
      const toMs = Date.parse(to);
      const windowMinutes = (toMs - fromMs) / 60_000;
      const date = to.slice(0, 10);
      const FLOOR_PER_10MIN = 150;
      const MULTIPLIER = 6;
      const outRows: Candidate[] = [];
      for (const row of out.result.rows as Record<string, unknown>[]) {
        const client = String(row.client ?? "");
        const count = Number(row.c ?? 0);
        if (!client) continue;
        const avgHourly = baseline[client] ?? 0;
        const floorScaled = FLOOR_PER_10MIN * (windowMinutes / 10);
        const baselineScaled = avgHourly * MULTIPLIER * (windowMinutes / 60);
        if (count < Math.max(floorScaled, baselineScaled)) continue;
        outRows.push({
          key: `dns-volume:${client.slice(0, 10)}:${date}`,
          severity: "high",
          candidate: {
            clientHash: client,
            candidateCount: count,
            baselineHourly: avgHourly,
            windowMinutes,
          },
        });
      }
      return outRows;
    },
  },
  {
    id: "ssh-brute-force",
    mitreTag: "T1110.001",
    primaryTable: "homelab.syslog",
    intervalMs: 0,
    cooldownMs: 6 * 3600_000,
    maxPerHour: 3,
    pausedMs: 2 * 3600_000,
    severity: "high",
    enabled: true,
    suppressible: true,
    scan: async (env, from, to) => {
      const rows = await overviewMemo(env, from, to);
      const date = to.slice(0, 10);
      const outRows: Candidate[] = [];
      const qualifying: { host: string; fail: number; ok: number }[] = [];
      for (const r of rows) {
        const host = String(r.host ?? "");
        const fail = Number(r.auth_fail ?? 0);
        const ok = Number(r.auth_ok ?? 0);
        if (!host || fail < SSH_FLOOR_PER_10MIN) continue;
        qualifying.push({ host, fail, ok });
      }
      if (qualifying.length === 0) return [];
      // Targeted enrichment (run-8 challenger): the triage question is
      // WHO is failing, not just how many. One bounded follow-up over the
      // same window, only when a candidate exists; the length cap keeps
      // regexp fall-through (whole message) out of the result.
      const src = await executeGoverned(
        env,
        "system",
        `SELECT host, ip, COUNT(*) AS c FROM ( ` +
          `SELECT host, regexp_replace(message, '^.*from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}).*$', '$1') AS ip ` +
          `FROM homelab.syslog WHERE __ingest_ts >= '${from}' AND __ingest_ts < '${to}' ` +
          `AND (message ILIKE '%failed password%' OR message ILIKE '%invalid user%') ` +
          `) WHERE ip LIKE '%.%.%.%' AND length(ip) <= 15 ` +
          `GROUP BY host, ip ORDER BY c DESC LIMIT 20`,
        { primaryTable: "homelab.syslog", skipExplain: true },
      );
      const sourcesByHost = new Map<string, { ip: string; count: number }[]>();
      if (src.ok) {
        for (const r of src.result.rows as Record<string, unknown>[]) {
          const host = String(r.host ?? "");
          const ip = String(r.ip ?? "");
          if (!host || !ip) continue;
          const list = sourcesByHost.get(host) ?? [];
          list.push({ ip, count: Number(r.c ?? 0) });
          sourcesByHost.set(host, list);
        }
      }
      for (const q of qualifying) {
        const escalated = q.ok >= 1 && q.fail >= SSH_ESCALATE_MIN_FAILS;
        outRows.push({
          key: `ssh-brute-force:${q.host}:${date}`,
          severity: escalated ? "critical" : "high",
          candidate: {
            host: q.host,
            authFail: q.fail,
            authOk: q.ok,
            escalated,
            topSources: (sourcesByHost.get(q.host) ?? [])
              .sort((a, b) => b.count - a.count)
              .slice(0, 3),
          },
        });
      }
      return outRows;
    },
  },
  {
    id: "host-distress",
    mitreTag: null,
    primaryTable: "homelab.syslog",
    intervalMs: 0,
    cooldownMs: 6 * 3600_000,
    maxPerHour: 3,
    pausedMs: 2 * 3600_000,
    severity: "high",
    enabled: true,
    suppressible: true,
    scan: async (env, from, to) => {
      const rows = await overviewMemo(env, from, to);
      const date = to.slice(0, 10);
      const outRows: Candidate[] = [];
      const qualifying: { host: string; oom: number; distress: number; total: number }[] = [];
      for (const r of rows) {
        const host = String(r.host ?? "");
        const oom = Number(r.oom ?? 0);
        const distress = Number(r.distress ?? 0);
        if (!host || (oom < 1 && distress < DISTRESS_LOOP_COUNT)) continue;
        qualifying.push({ host, oom, distress, total: Number(r.total ?? 0) });
      }
      if (qualifying.length === 0) return [];
      // Targeted enrichment: which unit failed. Live shape (verified
      // 2026-11-01): "<unit>.service: Main process exited, code=...".
      // The CASE WHEN keeps unmatched lines NULL instead of falling
      // through to the whole message.
      const units = await executeGoverned(
        env,
        "system",
        `SELECT host, unit, COUNT(*) AS c FROM ( ` +
          `SELECT host, CASE WHEN message ILIKE '%: Main process exited%' OR message ILIKE '%: Failed to start%' ` +
          `OR message ILIKE '%: Scheduled restart%' THEN substr(regexp_replace(message, ` +
          `'^([^:]{1,60}): (Main process exited|Failed to start|Scheduled restart).*$', '$1'), 1, 60) ` +
          `ELSE NULL END AS unit FROM homelab.syslog ` +
          `WHERE __ingest_ts >= '${from}' AND __ingest_ts < '${to}' ` +
          `AND (message ILIKE '%main process exited%' OR message ILIKE '%failed to start%' ` +
          `OR message ILIKE '%scheduled restart%') ` +
          `) WHERE unit IS NOT NULL GROUP BY host, unit ORDER BY c DESC LIMIT 10`,
        { primaryTable: "homelab.syslog", skipExplain: true },
      );
      const unitByHost = new Map<string, string>();
      if (units.ok) {
        for (const r of units.result.rows as Record<string, unknown>[]) {
          const host = String(r.host ?? "");
          if (host && !unitByHost.has(host)) unitByHost.set(host, String(r.unit ?? ""));
        }
      }
      for (const q of qualifying) {
        outRows.push({
          key: `host-distress:${q.host}:${date}`,
          severity: "high",
          candidate: {
            host: q.host,
            oom: q.oom,
            distress: q.distress,
            total: q.total,
            sampleUnit: unitByHost.get(q.host) ?? "",
          },
        });
      }
      return outRows;
    },
  },
  {
    // Monitor the monitor: reads the freshness meta snapshot and the
    // relay heartbeat meta - never queries Basin (run-5 cost amendment).
    id: "telemetry-blind-spot",
    mitreTag: null,
    primaryTable: null,
    intervalMs: 15 * 60_000,
    cooldownMs: 12 * 3600_000,
    maxPerHour: 2,
    pausedMs: 1 * 3600_000,
    severity: "high",
    enabled: true,
    suppressible: false, // monitor-the-monitor: never silently suppressible
    scan: async (env) => {
      const outRows: Candidate[] = [];
      const date = new Date().toISOString().slice(0, 10);
      const fresh = await metaGetJson(env, "freshness");
      const perTable =
        (fresh?.perTable as Record<string, number | null> | undefined) ?? {};
      const checkedAt = String(fresh?.checkedAt ?? "");
      const checkedAgeMs = checkedAt ? Date.now() - Date.parse(checkedAt) : Infinity;
      if (checkedAgeMs > 40 * 60_000) {
        // The freshness probe itself is stale: report that as the blind spot.
        outRows.push({
          key: `telemetry-blind-spot:freshness-probe:${date}`,
          severity: "high",
          candidate: {
            source: "freshness-probe",
            detail: "the freshness snapshot itself is older than 40 minutes",
          },
        });
      } else {
        for (const t of EXPECTED_FLOWING) {
          const ageSec = perTable[t];
          if (ageSec === null || ageSec === undefined) continue; // probe failure: disclosed separately
          if (ageSec * 1000 > BLINDSPOT_TABLE_AGE_MS) {
            outRows.push({
              key: `telemetry-blind-spot:${t}:${date}`,
              severity: "high",
              candidate: { source: t, detail: `newest row is ${Math.round(ageSec / 60)} minutes old`, checkedAt },
            });
          }
        }
      }
      const vectorLast = await metaGet(env, "vector_last_sample_at");
      if (!vectorLast || Date.now() - Date.parse(vectorLast) > BLINDSPOT_VECTOR_AGE_MS) {
        outRows.push({
          key: `telemetry-blind-spot:vector-relay:${date}`,
          severity: "high",
          candidate: {
            source: "vector-relay",
            detail: "no relay batch processed recently",
            lastSampleAt: vectorLast ?? "never",
          },
        });
      }
      return outRows;
    },
  },
  {
    // Self-monitoring is deliberate: this account runs exactly one Worker
    // (live-probed 2026-10-26: every ScriptName is basin-flowviz), so the
    // honest scope is the demo's own health. The catalogue's recursion
    // caveat is handled by coalescing: at most one report per cooldown.
    id: "worker-errors",
    mitreTag: null,
    primaryTable: "cfwork.workers_trace_events",
    intervalMs: 15 * 60_000,
    cooldownMs: 6 * 3600_000,
    maxPerHour: 2,
    pausedMs: 1 * 3600_000,
    severity: "medium",
    enabled: true,
    suppressible: false, // whole-app scope: close only
    scan: async (env, from, to) => {
      const out = await executeGoverned(
        env,
        "system",
        `SELECT "ScriptName" AS sn, "Outcome" AS o, COUNT(*) AS c FROM cfwork.workers_trace_events ` +
          `WHERE __ingest_ts >= '${from}' AND __ingest_ts < '${to}' AND "Outcome" != 'ok' ` +
          `GROUP BY "ScriptName", "Outcome" LIMIT 50`,
        { primaryTable: "cfwork.workers_trace_events", skipExplain: true },
      );
      if (!out.ok) return [];
      let bad = 0;
      const breakdown: Record<string, number> = {};
      const scripts: Record<string, number> = {};
      for (const r of out.result.rows as Record<string, unknown>[]) {
        const o = String(r.o ?? "?");
        const sn = String(r.sn ?? "?");
        const c = Number(r.c ?? 0);
        breakdown[o] = c;
        scripts[sn] = (scripts[sn] ?? 0) + c;
        bad += c;
      }
      if (bad < WORKER_ERROR_BURST) return [];
      return [
        {
          key: `worker-errors:${to.slice(0, 13)}`,
          severity: "medium",
          candidate: { bad, breakdown, scripts },
        },
      ];
    },
  },
  {
    id: "wifi-degradation",
    mitreTag: null,
    primaryTable: "homelab.host_metrics",
    intervalMs: 15 * 60_000,
    cooldownMs: 6 * 3600_000,
    maxPerHour: 2,
    pausedMs: 1 * 3600_000,
    severity: "medium",
    enabled: true,
    suppressible: true,
    scan: async (env, from, to) => {
      const outRows: Candidate[] = [];
      const date = to.slice(0, 10);
      // Client link quality: signal plus the tags a triager needs (which
      // AP, which band/channel, how happy the client is, noise floor).
      // Live-verified 2026-11-01: every tag extracts with the CASE-guarded
      // regexp patterns.
      const clients = await executeGoverned(
        env,
        "system",
        `SELECT host AS client, ROUND(AVG(${WIFI_SIG}),1) AS avg_signal, COUNT(*) AS n, ` +
          `MAX(${WIFI_STR("ap")}) AS ap, ` +
          `ROUND(AVG(${WIFI_NUM("channel")}),0) AS chan, ` +
          `ROUND(AVG(${WIFI_NUM("satisfaction")}),1) AS avg_sat, ` +
          `ROUND(AVG(${WIFI_NUM("noise")}),1) AS avg_noise ` +
          `FROM homelab.host_metrics WHERE __ingest_ts >= '${from}' AND __ingest_ts < '${to}' ` +
          `AND fields ILIKE '%wifi_client%' GROUP BY host HAVING COUNT(*) >= 5 LIMIT 100`,
        { primaryTable: "homelab.host_metrics", skipExplain: true },
      );
      if (clients.ok) {
        for (const r of clients.result.rows as Record<string, unknown>[]) {
          const client = String(r.client ?? "");
          const sig = Number(r.avg_signal ?? 0);
          if (!client || sig >= WIFI_SIG_FLOOR_DBM) continue;
          outRows.push({
            key: `wifi-degradation:${client}:${date}`,
            severity: "medium",
            candidate: {
              scope: "client",
              client,
              ap: String(r.ap ?? ""),
              channel: Number(r.chan ?? 0),
              avgSignal: sig,
              avgSatisfaction: Number(r.avg_sat ?? 0),
              avgNoise: Number(r.avg_noise ?? 0),
              samples: Number(r.n ?? 0),
            },
          });
        }
      }
      // AP airtime saturation, grouped per radio (run-8 challenger P1:
      // grouping by host alone merged the 2.4 GHz and 5 GHz radios into
      // one meaningless average; each radio is its own incident now).
      const radioExpr = WIFI_STR("radio");
      const aps = await executeGoverned(
        env,
        "system",
        `SELECT host AS ap, ${radioExpr} AS radio, ROUND(AVG(${WIFI_SIG}),1) AS avg_cu, COUNT(*) AS n, ` +
          `ROUND(AVG(${WIFI_NUM("channel")}),0) AS chan, ` +
          `ROUND(AVG(${WIFI_NUM("num_sta")}),1) AS avg_sta, ` +
          `ROUND(AVG(${WIFI_NUM("tx_retries_pct")}),1) AS avg_retry_pct, ` +
          `ROUND(AVG(${WIFI_NUM("satisfaction")}),1) AS avg_sat ` +
          `FROM homelab.host_metrics WHERE __ingest_ts >= '${from}' AND __ingest_ts < '${to}' ` +
          `AND fields ILIKE '%wifi_ap_radio%' GROUP BY host, ${radioExpr} ` +
          `HAVING COUNT(*) >= 5 LIMIT 50`,
        { primaryTable: "homelab.host_metrics", skipExplain: true },
      );
      if (aps.ok) {
        for (const r of aps.result.rows as Record<string, unknown>[]) {
          const ap = String(r.ap ?? "");
          const radio = String(r.radio ?? "");
          const cu = Number(r.avg_cu ?? 0);
          if (!ap || cu <= WIFI_AP_CU_FLOOR) continue;
          outRows.push({
            key: `wifi-degradation:${ap}/${radio || "radio"}:${date}`,
            severity: "medium",
            candidate: {
              scope: "ap",
              ap,
              radio,
              channel: Number(r.chan ?? 0),
              avgCuTotal: cu,
              avgNumSta: Number(r.avg_sta ?? 0),
              avgTxRetriesPct: Number(r.avg_retry_pct ?? 0),
              avgSatisfaction: Number(r.avg_sat ?? 0),
              samples: Number(r.n ?? 0),
            },
          });
        }
      }
      return outRows;
    },
  },
  {
    // AP-radio airtime congestion: cu_total saturation corroborated by
    // client satisfaction, station count or retry percentage (run-8
    // design; challenger: retries alone are NOT a congestion signal at
    // this site - LivingRoom runs 19.6% retries on a 27.7% cu day).
    // Client-side unhappiness stays in wifi-degradation; this detector
    // is AP-radio scoped only.
    id: "wifi-congestion",
    mitreTag: null,
    primaryTable: "homelab.host_metrics",
    intervalMs: 15 * 60_000,
    cooldownMs: 6 * 3600_000,
    maxPerHour: 2,
    pausedMs: 1 * 3600_000,
    severity: "medium",
    enabled: true,
    suppressible: true,
    scan: async (env, from, to) => {
      const outRows: Candidate[] = [];
      const date = to.slice(0, 10);
      const radioExpr = WIFI_STR("radio");
      const radios = await executeGoverned(
        env,
        "system",
        `SELECT host AS ap, ${radioExpr} AS radio, ` +
          `ROUND(AVG(${WIFI_SIG}),1) AS avg_cu, ROUND(MAX(${WIFI_SIG}),1) AS max_cu, COUNT(*) AS n, ` +
          `ROUND(AVG(${WIFI_NUM("channel")}),0) AS chan, ` +
          `ROUND(AVG(${WIFI_NUM("num_sta")}),1) AS avg_sta, ` +
          `ROUND(AVG(${WIFI_NUM("tx_retries_pct")}),1) AS avg_retry_pct, ` +
          `ROUND(AVG(${WIFI_NUM("satisfaction")}),1) AS avg_sat ` +
          `FROM homelab.host_metrics WHERE __ingest_ts >= '${from}' AND __ingest_ts < '${to}' ` +
          `AND fields ILIKE '%wifi_ap_radio%' GROUP BY host, ${radioExpr} ` +
          `HAVING COUNT(*) >= ${WIFI_CONGESTION_MIN_SAMPLES} LIMIT 50`,
        { primaryTable: "homelab.host_metrics", skipExplain: true },
      );
      if (radios.ok) {
        for (const r of radios.result.rows as Record<string, unknown>[]) {
          const ap = String(r.ap ?? "");
          const radio = String(r.radio ?? "");
          const avgCu = Number(r.avg_cu ?? 0);
          const avgSat = Number(r.avg_sat ?? 0);
          const avgSta = Number(r.avg_sta ?? 0);
          const avgRetryPct = Number(r.avg_retry_pct ?? 0);
          if (!ap) continue;
          if (!congestionFires(avgCu, avgSat, avgSta, avgRetryPct, Number(r.n ?? 0)))
            continue;
          outRows.push({
            key: `wifi-congestion:${ap}/${radio || "radio"}:${date}`,
            severity: "medium",
            candidate: {
              ap,
              radio,
              channel: Number(r.chan ?? 0),
              avgCuTotal: avgCu,
              maxCuTotal: Number(r.max_cu ?? 0),
              avgNumSta: avgSta,
              avgTxRetriesPct: avgRetryPct,
              avgSatisfaction: avgSat,
              samples: Number(r.n ?? 0),
            },
          });
        }
      }
      return outRows;
    },
  },
  {
    // WAN lease-level outage detection (run-8). The edge router syslog
    // carries a steady DHCP-renewal heartbeat (4/hour, 3-day verified
    // cadence, no gaps). Renewals stopping while the router still logs
    // other traffic means the WAN link dropped; the router going fully
    // silent means WAN state is unknowable from telemetry. The router
    // host is configured via roles.routerHost in the local catalogue
    // overlay (never committed): without it this detector is inert and
    // the coverage card says so.
    id: "wan-outage",
    mitreTag: null,
    primaryTable: "homelab.syslog",
    intervalMs: 15 * 60_000,
    cooldownMs: 6 * 3600_000,
    maxPerHour: 2,
    pausedMs: 1 * 3600_000,
    severity: "high",
    enabled: true,
    suppressible: true,
    gatedNote:
      "needs roles.routerHost in the local catalogue overlay (the real syslog hostname of the edge router); neutral builds stay inert",
    scan: async (env, from, to) => {
      const router = catalog.roles?.routerHost ?? "";
      if (!router) return [];
      const rh = sqlLit(router);
      const date = to.slice(0, 10);
      // One fused liveness query (bounded to 2 hours: the heartbeat is
      // 15-minute cadence, so the lookback holds >= 8 renewal events).
      const liveness = await executeGoverned(
        env,
        "system",
        `SELECT MAX(CASE WHEN message ILIKE '%udhcpc%' THEN __ingest_ts END) AS last_wan, ` +
          `MAX(__ingest_ts) AS last_any, ` +
          `COUNT(CASE WHEN message ILIKE '%udhcpc%' THEN 1 END) AS renewals ` +
          `FROM homelab.syslog WHERE __ingest_ts >= now() - INTERVAL '${WAN_LOOKBACK}' AND host = ${rh}`,
        { primaryTable: "homelab.syslog", skipExplain: true },
      );
      // Latest leased WAN IP (regexp fall-through guard: only lines that
      // match "lease of <ip> obtained" extract, so the result is an IP
      // or NULL, never message text).
      const lease = await executeGoverned(
        env,
        "system",
        `SELECT substr(regexp_replace(message, '^.*lease of ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}) obtained.*$', '$1'), 1, 15) AS ip ` +
          `FROM homelab.syslog WHERE __ingest_ts >= now() - INTERVAL '${WAN_LOOKBACK}' AND host = ${rh} ` +
          `AND message ILIKE '%lease of%obtained%' ORDER BY __ingest_ts DESC LIMIT 1`,
        { primaryTable: "homelab.syslog", skipExplain: true },
      );
      const row = (liveness.ok ? liveness.result.rows[0] : undefined) as
        | { last_wan?: string | null; last_any?: string | null; renewals?: number }
        | undefined;
      const wanIpRaw = (lease.ok ? lease.result.rows[0] : undefined) as { ip?: string } | undefined;
      // TS-side guard: only accept a well-formed IPv4 literal (the SQL
      // regexp should never fall through past the ILIKE guard, but a
      // truncated message must never be persisted as an "IP").
      const wanIp = /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(String(wanIpRaw?.ip ?? ""))
        ? String(wanIpRaw?.ip)
        : "";
      const lastWanMs = row?.last_wan ? Date.parse(String(row.last_wan)) : null;
      const lastAnyMs = row?.last_any ? Date.parse(String(row.last_any)) : null;
      const renewals = Number(row?.renewals ?? 0);
      const prevIp = await metaGet(env, "wan-outage:ip");
      const outRows: Candidate[] = [];
      for (const v of wanVerdicts(Date.now(), lastWanMs, lastAnyMs, wanIp, prevIp)) {
        const context: Record<string, unknown> = {
          scope: v.scope,
          routerHost: router,
          renewalsInLookback: renewals,
          ...v.context,
        };
        if (v.scope === "ip-change") {
          context.previousIp = prevIp ?? "";
          context.wanIp = wanIp;
        }
        outRows.push({
          key: `wan-outage:${v.scope}:${date}`,
          severity: v.severity,
          candidate: context,
        });
      }
      if (wanIp) await metaSet(env, "wan-outage:ip", wanIp).catch(() => {});
      return outRows;
    },
  },
  {
    // Gated on telemetry: Vector's host_metrics emits disk IO counters and
    // process metrics but no filesystem utilization (live-probed
    // 2026-10-26). Enabling the filesystem collector in Vector is an
    // ingestion change that needs owner approval; until then this
    // detector documents itself as gated on the coverage card.
    id: "disk-exhaustion",
    mitreTag: null,
    primaryTable: null,
    intervalMs: 0,
    cooldownMs: 24 * 3600_000,
    maxPerHour: 1,
    pausedMs: 1 * 3600_000,
    severity: "medium",
    enabled: false,
    suppressible: true,
    gatedNote:
      "needs a filesystem utilization metric: add the disk/filesystem collector to Vector's host_metrics source (ingestion change, owner approval)",
    scan: async () => [],
  },
];

export function detectorDef(id: string): DetectorDef | undefined {
  return DETECTORS.find((d) => d.id === id);
}

// ---------------------------------------------------------------------------
// scheduler: per-detector gate, breaker, watermark, coalesce, dispatch
// ---------------------------------------------------------------------------

async function breakerAllows(env: SchedulerEnv, def: DetectorDef): Promise<boolean> {
  const globalPaused = await metaGet(env, "detectors_global_paused_until");
  if (globalPaused && Date.parse(globalPaused) > Date.now()) return false;
  const paused = await metaGet(env, `detectors_paused_until_${def.id}`);
  if (paused && Date.parse(paused) > Date.now()) return false;
  if (!env.REPORTS_D1 || !def.enabled) return def.enabled;
  const r = await env.REPORTS_D1.prepare(
    "SELECT COUNT(*) AS c FROM reports WHERE playbook = ?1 AND created_at >= ?2",
  )
    .bind(def.id, new Date(Date.now() - 3600_000).toISOString())
    .first<{ c: number }>();
  if ((r?.c ?? 0) > def.maxPerHour) {
    await metaSet(env, `detectors_paused_until_${def.id}`, new Date(Date.now() + def.pausedMs).toISOString());
    // A detector at its own limit also arms the global ceiling so one
    // incident cannot flood the whole inbox.
    const all = await env.REPORTS_D1.prepare(
      "SELECT COUNT(*) AS c FROM reports WHERE created_at >= ?1",
    )
      .bind(new Date(Date.now() - 3600_000).toISOString())
      .first<{ c: number }>();
    if ((all?.c ?? 0) > 10) {
      await metaSet(env, "detectors_global_paused_until", new Date(Date.now() + def.pausedMs).toISOString());
    }
    return false;
  }
  return true;
}

async function runOne(env: SchedulerEnv, def: DetectorDef): Promise<void> {
  if (!env.BASIN_SQL_TOKEN || !env.REPORTS_D1) return;
  if (!def.enabled) return;

  // Cadence gate: per-detector interval (0 = every tick, like dns-volume).
  if (def.intervalMs > 0) {
    const gate = await metaGet(env, `gate_detector_${def.id}`);
    if (gate && Date.now() - Date.parse(gate) < def.intervalMs) return;
    await metaSet(env, `gate_detector_${def.id}`, new Date().toISOString());
  }
  if (!(await breakerAllows(env, def))) return;

  const now = Date.now();
  const toMs = now - LAG_GUARD_MS;
  let fromMs = toMs - 10 * 60_000;
  const w = await env.REPORTS_D1.prepare("SELECT window_end FROM watermarks WHERE detector_id = ?1")
    .bind(def.id)
    .first<{ window_end: string }>();
  const watermark = w?.window_end ?? null;
  if (watermark) {
    const wm = Date.parse(watermark);
    if (Number.isFinite(wm)) fromMs = Math.max(Math.min(fromMs, wm - OVERLAP_MS), toMs - 30 * 60_000);
  }
  const from = new Date(fromMs).toISOString();
  const to = new Date(toMs).toISOString();
  if (fromMs >= toMs) {
    await env.REPORTS_D1.prepare(
      "INSERT INTO watermarks (detector_id, window_end, updated_at) VALUES (?1, ?2, ?3) " +
        "ON CONFLICT(detector_id) DO UPDATE SET window_end = ?2, updated_at = ?3, status = 'active'",
    )
      .bind(def.id, to, new Date().toISOString())
      .run();
    return;
  }
  // Move the watermark before scanning so a failure re-scans only overlap.
  await env.REPORTS_D1.prepare(
    "INSERT INTO watermarks (detector_id, window_end, updated_at) VALUES (?1, ?2, ?3) " +
      "ON CONFLICT(detector_id) DO UPDATE SET window_end = ?2, updated_at = ?3, status = 'active', enabled = 1",
  )
    .bind(def.id, to, new Date().toISOString())
    .run();

  let candidates: Candidate[] = [];
  try {
    candidates = await def.scan(env, from, to);
  } catch (e) {
    await env.REPORTS_D1.prepare(
      "UPDATE watermarks SET status = 'error', last_error = ?2 WHERE detector_id = ?1",
    )
      .bind(def.id, String(e instanceof Error ? e.message : e).slice(0, 200))
      .run();
    return;
  }

  // Round 6: batch-fetch active suppressions for this detector's
  // candidate keys (one D1 read, not N+1), then consult per candidate.
  const suppressionMap = def.suppressible
    ? await fetchSuppressions(env, def.id, candidates.map((c) => c.key))
    : new Map<string, ActiveSuppression>();

  for (const cand of candidates) {
    // Suppressed: increment the hit count, produce no report.
    const pk = def.suppressible ? patternKey(cand.key, def.id) : null;
    if (pk && suppressionMap.has(pk)) {
      await env.REPORTS_D1.prepare(
        "UPDATE suppressions SET count = count + 1 WHERE detector_id = ?1 AND pattern_key = ?2",
      )
        .bind(def.id, pk)
        .run()
        .catch(() => {});
      continue;
    }

    // Coalescence: only into active (open/read) reports - a triaged
    // (closed) report must never swallow a future detection.
    const recent = await env.REPORTS_D1.prepare(
      "SELECT id, updated_at FROM reports WHERE incident_key = ?1 AND status IN ('open','read') ORDER BY updated_at DESC LIMIT 1",
    )
      .bind(cand.key)
      .first<{ id: string; updated_at: string }>();
    if (recent && Date.now() - Date.parse(recent.updated_at) < def.cooldownMs) {
      // Coalesced: refresh the case timestamp and the inbox preview
      // (run-8 challenger: without this, recurring incidents keep a
      // stale or missing preview line), do not create a new instance.
      await env.REPORTS_D1.prepare(
        "UPDATE reports SET last_seen_at = ?2, updated_at = ?2, preview = ?3 WHERE id = ?1",
      )
        .bind(recent.id, new Date().toISOString(), buildPreview(def.id, cand.candidate))
        .run();
      continue;
    }
    if (!env.INVESTIGATIONS) continue;
    await env.INVESTIGATIONS.create({
      id: `inv-${def.id}-${cand.key.replace(/[^a-z0-9-]/gi, "").slice(0, 40)}-${Date.now()}`,
      params: {
        detectorId: def.id,
        severity: cand.severity,
        incidentKey: cand.key,
        windowFrom: from,
        windowTo: to,
        detectedAt: new Date().toISOString(),
        candidate: cand.candidate,
      },
    }).catch(() => {});
  }
}

export async function runDetectors(env: SchedulerEnv): Promise<void> {
  if (!env.BASIN_SQL_TOKEN) return;
  await refreshBaselines(env).catch(() => {});
  for (const def of DETECTORS) {
    await runOne(env, def).catch(() => {});
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
        "ON CONFLICT(table_id) DO UPDATE SET ok = ?2, checked_at = ?3, detail = ?4",
    )
      .bind(t.id, ok ? 1 : 0, now.toISOString(), detail)
      .run();
  }
  await metaSet(env, "drift_last_run", now.toISOString());
}
