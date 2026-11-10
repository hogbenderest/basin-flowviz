// Run 9: the agentic investigate loop. A bounded, multi-step analysis of
// one host's logs for causal questions ("why did the HTPC server
// crash?"). Steps: entity resolution -> hourly volume + distress classes
// -> silence-gap detection -> tail extraction around each gap ->
// deterministic classification -> verdict synthesis over AGGREGATES ONLY.
//
// Safety contract (challenger-reviewed):
// - the model's raw entity string is resolved against curated + observed
//   host sets server-side; only the canonical value reaches SQL (sqlLit)
// - raw log lines NEVER reach any model; they land in evidence snapshots
//   for the human only
// - hard budget: at most 6 governed queries and 2 model calls per
//   investigation (planner + synthesis), with rateLimitInvestigate
//   (3 per user per 10 minutes) on top of the ask limits
// - every query is snapshotted as evidence; the outcome is filed as an
//   inbox report so the verdict outlives the HTTP request.

import { executeGoverned, snapshotEvidence, rateLimitInvestigate } from "../query/service";
import { catalog } from "../catalog/render";
import { sqlLit } from "../sql";
import {
  hourlyVolumeSql,
  classifyLine,
  classColumn,
  classLabel,
  CLASS_IDS,
  type LineClassId,
} from "../investigate/taxonomy";
import { synthesizeVerdict, type InvestigationSynthesis, type PlanSession } from "./planner";
import { persistReport } from "../investigate/persist";
import { buildPreview } from "../investigate/preview";
import type {
  QueryPlan,
  EvidenceRecord,
  InvestigationReport,
  ChartSpec,
  AskResponse,
} from "../catalog/types";
import type { ServiceEnv } from "../bindings";

const MAX_QUERIES = 6;
const MAX_GAPS = 2;
const TAIL_BEFORE = 100;
const TAIL_AFTER = 50;
const TAIL_BEFORE_LOOKBACK_MS = 6 * 3600_000;
const TAIL_AFTER_WINDOW_MS = 30 * 60_000;

// ---------------------------------------------------------------------------
// entity resolution (server-side; the model string never reaches SQL)
// ---------------------------------------------------------------------------

export interface ResolvedEntity {
  host: string;
  label: string;
  curated: boolean;
}

export type EntityResolution =
  | { ok: true; entity: ResolvedEntity }
  | { ok: false; kind: "empty"; note: string }
  | { ok: false; kind: "ambiguous"; candidates: string[]; note: string };

interface ObservedHost {
  host: string;
  lastSeen: string;
}

async function observedHosts(env: ServiceEnv): Promise<ObservedHost[]> {
  if (!env.REPORTS_D1) return [];
  try {
    const r = await env.REPORTS_D1.prepare("SELECT value FROM meta WHERE key = ?1")
      .bind("observed_hosts")
      .first<{ value: string }>();
    if (!r?.value) return [];
    const parsed = JSON.parse(r.value) as ObservedHost[];
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((h) => h && typeof h.host === "string" && h.host)
      .slice(0, 100);
  } catch {
    return [];
  }
}

export async function resolveEntity(env: ServiceEnv, raw: string): Promise<EntityResolution> {
  const token = String(raw ?? "").trim();
  const curated = catalog.hosts ?? [];
  const observed = await observedHosts(env);
  // Union of known host ids, lowercase keyed; curated wins on labels.
  const byLower = new Map<string, ResolvedEntity>();
  for (const o of observed) {
    byLower.set(o.host.toLowerCase(), { host: o.host, label: o.host, curated: false });
  }
  for (const h of curated) {
    byLower.set(h.id.toLowerCase(), { host: h.id, label: h.label ?? h.id, curated: true });
  }
  const known = [...byLower.values()];
  if (!token) {
    return {
      ok: false,
      kind: "empty",
      note:
        known.length > 0
          ? `name a host to investigate; known hosts include: ${known.slice(0, 8).map((e) => e.host).join(", ")}`
          : "name a host to investigate",
    };
  }
  // 1. Exact (case-insensitive) match.
  const exact = byLower.get(token.toLowerCase());
  if (exact) return { ok: true, entity: exact };
  // 2. Containment match (either direction), still against known hosts
  // only: a hostile or sloppy model string can never broaden this.
  const tok = token.toLowerCase();
  const contained = known.filter(
    (e) => e.host.toLowerCase().includes(tok) || tok.includes(e.host.toLowerCase()),
  );
  if (contained.length === 1) return { ok: true, entity: contained[0] };
  if (contained.length > 1) {
    return {
      ok: false,
      kind: "ambiguous",
      candidates: contained.slice(0, 4).map((e) => e.host),
      note: "several hosts match that name; pick one",
    };
  }
  return {
    ok: false,
    kind: "empty",
    note: `"${token.slice(0, 40)}" is not a host this archive has seen; known hosts include: ${known
      .slice(0, 8)
      .map((e) => e.host)
      .join(", ")}`,
  };
}

// ---------------------------------------------------------------------------
// gap detection (pure; unit-tested)
// ---------------------------------------------------------------------------

export interface VolumeRow {
  bucket: string;
  total: number;
}

export interface LogGap {
  startMs: number;
  endMs: number;
  hours: number;
}

// Buckets only exist where rows exist, so silence is reconstructed hour
// by hour across the window. The normal-pause estimate deliberately
// EXCLUDES the longest zero-run (otherwise one incident inflates its own
// threshold); with nothing left, a 0.5h default applies. A gap must
// clear 3x the normal pause (>= 2h floor) to register.
export function detectGaps(fromMs: number, toMs: number, rows: VolumeRow[]): LogGap[] {
  const hour = 3600_000;
  const totals = new Map<number, number>();
  for (const r of rows) {
    const ms = Date.parse(r.bucket);
    if (Number.isFinite(ms)) totals.set(ms, Number(r.total ?? 0));
  }
  const start = Math.ceil(fromMs / hour) * hour;
  const end = Math.min(toMs, Date.now());
  // First walk: collect every zero-run's length (closed runs only).
  const runs: { startMs: number; hours: number }[] = [];
  let runStart: number | null = null;
  for (let t = start; t < end; t += hour) {
    const zero = (totals.get(t) ?? 0) === 0;
    if (zero) {
      if (runStart === null) runStart = t;
    } else if (runStart !== null) {
      runs.push({ startMs: runStart, hours: (t - runStart) / hour });
      runStart = null;
    }
  }
  // Trailing silence: an open run ending at the last checked hour.
  if (runStart !== null) runs.push({ startMs: runStart, hours: (end - runStart) / hour });

  // Normal-pause learning: exclude the single longest run (the likely
  // incident) and anything 24h+ (assumed incidents), then take the
  // lower median; default 0.5h when no baseline remains.
  const sorted = [...runs].sort((a, b) => b.hours - a.hours);
  const learning = sorted
    .slice(1)
    .map((r) => r.hours)
    .filter((h) => h < 24 && h > 0)
    .sort((a, b) => a - b);
  const medianPause = learning.length
    ? learning[Math.max(0, Math.floor((learning.length - 1) / 2))]
    : 0.5;
  const thresholdHours = Math.max(2, Math.ceil(medianPause * 3));

  const gaps: LogGap[] = [];
  for (const r of runs) {
    if (r.hours >= thresholdHours) {
      gaps.push({ startMs: r.startMs, endMs: r.startMs + r.hours * hour, hours: r.hours });
    }
  }
  return gaps.sort((a, b) => b.hours - a.hours).slice(0, MAX_GAPS);
}

// A gap is "pipeline-shaped" when the rest of the syslog table went
// quiet in the same hours: a global ingestion hole, not evidence about
// this host. Without this check any pipeline outage would misdiagnose
// every host as crashed (live-caught 2026-11-10: a 19h hole made the
// always-on router look "abruptly stopped").
export interface GlobalRow {
  bucket: string;
  total: number;
}

export function gapPipelineShaped(global: GlobalRow[], gap: LogGap): boolean {
  const hour = 3600_000;
  const totals = new Map<number, number>();
  for (const r of global) {
    const ms = Date.parse(r.bucket);
    if (Number.isFinite(ms)) totals.set(ms, Number(r.total ?? 0));
  }
  let zero = 0;
  let n = 0;
  for (let t = Math.ceil(gap.startMs / hour) * hour; t < gap.endMs; t += hour) {
    n++;
    if ((totals.get(t) ?? 0) === 0) zero++;
  }
  return n > 0 && zero / n >= 0.8;
}

// A clean stop logs a shutdown cascade in its final lines; an abrupt
// stop does not. These needles are deliberately the strict systemd
// targets, not the broad "%Stopping%" (a unit restart also logs stops).
const SHUTDOWN_NEEDLES = [
  "reached target shutdown",
  "reached target reboot",
  "reached target poweroff",
  "reached target exit.target",
  "powering off",
  "the system is going down",
];
const BOOT_NEEDLES = ["startup finished", "welcome to", "reached target basic.target", "reached target graphical"];

function hasNeedle(lines: { message?: string }[], needles: string[]): boolean {
  return lines.some((l) => {
    const m = String(l.message ?? "").toLowerCase();
    return needles.some((n) => m.includes(n));
  });
}

// Did the user actually reference this entity? Tokens come from the
// warehouse id ONLY (label words like "wifi" would leak: a wifi question
// must not auto-reference the HTPC merely because its label mentions
// wifi). A plan whose entity the question never mentioned is the model
// guessing; guessing becomes clarify-chips rather than a silently
// misrouted investigation (run-9 honesty net). Paraphrases ("my media
// centre") surface the same chips, which is the honest shape.
export function entityReferenced(entityId: string, question: string): boolean {
  const q = question.toLowerCase();
  for (const m of entityId.toLowerCase().matchAll(/[a-z0-9]+/g)) {
    if (m[0].length >= 4 && q.includes(m[0])) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// the investigate loop
// ---------------------------------------------------------------------------

interface InvestigateStats {
  host: string;
  windowFromUTC: string;
  windowToUTC: string;
  windowHours: number;
  hourly: { bucket: string; total: number }[];
  totalsPerClass: Record<string, number>;
  gaps: {
    startUTC: string;
    endUTC: string;
    hours: number;
    abruptStop: boolean;
    cleanRestart: boolean;
    pipelineShaped: boolean;
    linesBefore: number;
    linesAfter: number;
    classesBefore: Record<string, number>;
    classesAfter: Record<string, number>;
  }[];
  linesInWindow: number;
}

export async function runInvestigation(
  env: ServiceEnv,
  user: string,
  question: string,
  plan: QueryPlan,
  session: PlanSession | undefined,
): Promise<AskResponse> {
  const notes: string[] = [];
  const evidence: EvidenceRecord[] = [];
  let queries = 0;
  const budget = async (sql: string, opts: { primaryTable: string }) => {
    queries++;
    return executeGoverned(env, user, sql, opts);
  };

  // Step 1: entity resolution (no governed query; D1 meta read only).
  const res = await resolveEntity(env, plan.entity ?? "");
  if (!res.ok) {
    if (res.kind === "ambiguous") {
      return {
        state: "ambiguous",
        question,
        ambiguities: res.candidates,
        notes: [res.note],
      };
    }
    return { state: "unsupported", question, notes: [res.note] };
  }
  const host = res.entity.host;

  // Window: session scope if present, else 7 days (crash forensics need
  // more lookback than the 24h default), clamped by the 30-day cap.
  const now = Date.now();
  const toMs = session?.toUTC ? Date.parse(session.toUTC) || now : now;
  const fromMs = session?.fromUTC
    ? Date.parse(session.fromUTC) || now - 7 * 86400_000
    : Math.max(now - 30 * 86400_000, toMs - 7 * 86400_000);
  const fromUTC = new Date(fromMs).toISOString();
  const toUTC = new Date(toMs).toISOString();

  // Step 2: hourly volume + distress classes over the window.
  const volumeOut = await budget(hourlyVolumeSql(host, fromUTC, toUTC, "hour", 200), {
    primaryTable: "homelab.syslog",
  });
  if (!volumeOut.ok) {
    return { state: "failed", question, notes: [volumeOut.error], plan };
  }
  const volumeRows = volumeOut.result.rows as Record<string, unknown>[];
  {
    const rec = await snapshotEvidence(env, {
      sql: hourlyVolumeSql(host, fromUTC, toUTC, "hour", 200),
      result: volumeOut.result,
      kind: "rows",
    });
    if (rec) evidence.push(rec);
  }

  const hourly: VolumeRow[] = volumeRows.map((r) => ({
    bucket: String(r.bucket ?? ""),
    total: Number(r.total ?? 0),
  }));
  const totalsPerClass: Record<string, number> = {};
  for (const id of CLASS_IDS) {
    totalsPerClass[id] = volumeRows.reduce((s, r) => s + Number(r[classColumn(id)] ?? 0), 0);
  }
  const linesInWindow = hourly.reduce((s, r) => s + r.total, 0);

  // Step 2b: global syslog volume for the same window (the pipeline-hole
  // cross-check: a host's silence during a global hole is ingestion
  // evidence, not host evidence).
  const globalOut = await budget(
    `SELECT date_trunc('hour', ts) AS bucket, COUNT(*) AS total, COUNT(DISTINCT host) AS hosts ` +
      `FROM homelab.syslog WHERE __ingest_ts >= ${sqlLit(fromUTC)} AND __ingest_ts < ${sqlLit(toUTC)} ` +
      `GROUP BY 1 ORDER BY bucket LIMIT 200`,
    { primaryTable: "homelab.syslog" },
  );
  const globalRows: GlobalRow[] = globalOut.ok
    ? (globalOut.result.rows as Record<string, unknown>[]).map((r) => ({
        bucket: String(r.bucket ?? ""),
        total: Number(r.total ?? 0),
      }))
    : [];

  // Step 3: gap detection.
  const gaps = detectGaps(fromMs, toMs, hourly);

  // Step 4 + 5: tails around each gap, classified deterministically.
  const gapStats: InvestigateStats["gaps"] = [];
  for (const g of gaps) {
    if (queries + 2 > MAX_QUERIES) {
      notes.push(`query budget reached: analysed ${gapStats.length} of ${gaps.length} gap(s)`);
      break;
    }
    const beforeOut = await budget(
      `SELECT substr(CAST(ts AS TEXT),1,19) AS ts, message FROM homelab.syslog ` +
        `WHERE host = ${sqlLit(host)} AND __ingest_ts >= ${sqlLit(new Date(g.startMs - TAIL_BEFORE_LOOKBACK_MS).toISOString())} ` +
        `AND __ingest_ts < ${sqlLit(new Date(g.startMs).toISOString())} ORDER BY ts DESC LIMIT ${TAIL_BEFORE}`,
      { primaryTable: "homelab.syslog" },
    );
    const afterOut =
      g.endMs < toMs && queries + 1 <= MAX_QUERIES
        ? await budget(
            `SELECT substr(CAST(ts AS TEXT),1,19) AS ts, message FROM homelab.syslog ` +
              `WHERE host = ${sqlLit(host)} AND __ingest_ts >= ${sqlLit(new Date(g.endMs).toISOString())} ` +
              `AND __ingest_ts < ${sqlLit(new Date(g.endMs + TAIL_AFTER_WINDOW_MS).toISOString())} ORDER BY ts ASC LIMIT ${TAIL_AFTER}`,
            { primaryTable: "homelab.syslog" },
          )
        : null;
    const before = beforeOut.ok
      ? (beforeOut.result.rows as { ts?: string; message?: string }[]).reverse()
      : [];
    const after = afterOut?.ok ? (afterOut.result.rows as { ts?: string; message?: string }[]) : [];
    if (beforeOut.ok) {
      const rec = await snapshotEvidence(env, {
        sql: `-- tail before gap: ${host}`,
        result: beforeOut.result,
        kind: "rows",
      });
      if (rec) evidence.push(rec);
    }
    if (afterOut?.ok) {
      const rec = await snapshotEvidence(env, {
        sql: `-- first lines after gap: ${host}`,
        result: afterOut.result,
        kind: "rows",
      });
      if (rec) evidence.push(rec);
    }
    const classesBefore: Record<string, number> = {};
    const classesAfter: Record<string, number> = {};
    for (const id of CLASS_IDS) {
      classesBefore[id] = 0;
      classesAfter[id] = 0;
    }
    for (const l of before) classesBefore[classifyLine(String(l.message ?? ""))]++;
    for (const l of after) classesAfter[classifyLine(String(l.message ?? ""))]++;
    const pipelineShaped = gapPipelineShaped(globalRows, g);
    gapStats.push({
      startUTC: new Date(g.startMs).toISOString(),
      endUTC: new Date(g.endMs).toISOString(),
      hours: Math.round(g.hours * 10) / 10,
      abruptStop: !hasNeedle(before, SHUTDOWN_NEEDLES) && before.length >= 3,
      cleanRestart: hasNeedle(after, BOOT_NEEDLES),
      pipelineShaped,
      linesBefore: before.length,
      linesAfter: after.length,
      classesBefore,
      classesAfter,
    });
  }

  // Step 6: synthesis over aggregates; deterministic fallback first.
  const stats: InvestigateStats = {
    host,
    windowFromUTC: fromUTC,
    windowToUTC: toUTC,
    windowHours: Math.round((toMs - fromMs) / 3600_000),
    hourly: hourly.slice(-168),
    totalsPerClass,
    gaps: gapStats,
    linesInWindow,
  };
  const fallback = deterministicVerdict(stats);
  const synthesis: InvestigationSynthesis = await synthesizeVerdict(env, question, stats as unknown as Record<string, unknown>, fallback);

  notes.push(
    "aggregates-only investigation: raw log lines are in the evidence rows below, never sent to any model",
    `${queries} governed quer${queries === 1 ? "y" : "ies"}; silence gaps are detected from hourly log volume, so a host that logs nothing for <2 consecutive hours may not register`,
  );
  if (gaps.length === 0) {
    notes.push(
      `no silence gap over the last ${stats.windowHours}h: if the incident is older, scope the session window or ask again with a wider timeframe`,
    );
  }

  // Chart: hourly totals, gaps visible via the gap policy.
  const chart: ChartSpec = {
    type: "time-series",
    title: `${host} log volume (lines per hour)`,
    x: "bucket",
    y: "total",
    missingDataPolicy: "gap",
    timeWindow: { fromUTC: fromUTC, toUTC: toUTC },
  };

  // File the outcome as an inbox report so it survives the request.
  await fileReport(env, user, host, stats, synthesis, evidence);

  return {
    state: "investigated",
    question,
    plan,
    verdict: synthesis.verdict,
    investigationFindings: synthesis.findings.map((f) => ({
      statement: f.statement,
      classification: f.classification,
    })),
    nextSteps: synthesis.nextSteps,
    chart,
    chartData: hourly,
    evidence,
    notes,
  };
}

// ---------------------------------------------------------------------------
// deterministic verdict (model-independent; the fallback of record)
// ---------------------------------------------------------------------------

export function deterministicVerdict(s: InvestigateStats): InvestigationSynthesis {
  const parts: string[] = [];
  const findings: { statement: string; classification: string }[] = [];
  const nextSteps: string[] = [];
  if (s.gaps.length === 0) {
    parts.push(
      `${s.host} shows no log silence over the last ${s.windowHours}h (${s.linesInWindow} lines). ` +
        `Either it did not stop, or the incident is outside this window.`,
    );
    nextSteps.push("widen the timeframe if the incident is older");
  }
  for (const g of s.gaps) {
    const at = new Date(g.startUTC).toISOString().replace("T", " ").slice(0, 16) + " UTC";
    if (g.pipelineShaped) {
      parts.push(
        `${s.host} is silent from ${at} for ${g.hours}h, but so is the rest of the syslog table ` +
          `(a global ingestion hole, not evidence about this host). ${s.host}'s last lines before the hole show ` +
          `${g.abruptStop ? "no shutdown cascade" : "a shutdown cascade"}; its state during the hole cannot be ` +
          `determined from this table.`,
      );
      findings.push({
        statement: `silence at ${at} matches a global syslog ingestion hole: pipeline outage, not host evidence`,
        classification: "supported",
      });
      nextSteps.push("check the syslog pipeline (Vector / ingest host) health for the hole window");
    } else if (g.abruptStop) {
      parts.push(
        `${s.host} stopped logging abruptly at ${at} (${g.hours}h silence, ${g.linesBefore} final lines, no shutdown cascade): ` +
          `a hard freeze, power cut, or a kernel panic that never reached disk. Logging resumed ${new Date(g.endUTC)
            .toISOString()
            .replace("T", " ")
            .slice(0, 16)} UTC${g.cleanRestart ? " with a clean boot cascade" : ""}.`,
      );
      findings.push({
        statement: `abrupt stop at ${at}: no shutdown cascade in the final ${g.linesBefore} lines`,
        classification: "supported",
      });
      nextSteps.push(`check ${s.host}'s power supply, temperature and kernel console for the stop time`);
    } else {
      parts.push(
        `${s.host} went silent at ${at} for ${g.hours}h after logging a shutdown cascade: this was a clean, logged stop, not a crash.`,
      );
      findings.push({
        statement: `clean stop at ${at}: shutdown cascade present in the final lines`,
        classification: "supported",
      });
    }
    const distressBefore = Object.entries(g.classesBefore).filter(([k, v]) => k !== "routine" && v > 0);
    if (distressBefore.length) {
      findings.push({
        statement: `patterns in the ${g.linesBefore} lines before silence: ${distressBefore
          .map(([k, v]) => `${v} ${classLabel(k as LineClassId)}`)
          .join(", ")}`,
        classification: "supported",
      });
    }
  }
  const classTotals = Object.entries(s.totalsPerClass).filter(([k, v]) => k !== "routine" && v > 0);
  if (classTotals.length) {
    parts.push(
      `In the window the logs carry ${classTotals.map(([k, v]) => `${v} ${classLabel(k as LineClassId)}`).join(", ")}.`,
    );
  }
  if (s.gaps.some((g) => g.abruptStop && !g.pipelineShaped)) {
    parts.push("Root cause (power loss vs kernel vs hardware) is not captured: the shipped logs end mid-routine.");
  }
  if (!parts.length) parts.push(`No conclusions available for ${s.host} in this window.`);
  return {
    verdict: parts.join(" "),
    confidence: s.gaps.length ? "medium" : "low",
    findings: findings.slice(0, 4),
    nextSteps: nextSteps.slice(0, 4),
    usedModel: false,
  };
}

// ---------------------------------------------------------------------------
// report filing: the investigation lands in the inbox like any detection
// ---------------------------------------------------------------------------

async function fileReport(
  env: ServiceEnv,
  user: string,
  host: string,
  stats: InvestigateStats,
  synthesis: InvestigationSynthesis,
  evidence: EvidenceRecord[],
): Promise<void> {
  try {
    const now = new Date();
    const date = now.toISOString().slice(0, 10);
    const incidentKey = `ask-investigation:${host}:${now.toISOString().slice(0, 13)}`;
    const safeKey = incidentKey.replace(/[^a-z0-9-]/gi, "").slice(-24);
    const findings = (synthesis.findings ?? []).map((f, i) => ({
      id: `f${i + 1}`,
      statement: f.statement,
      evidence: evidence[0] ? [evidence[0].id] : [],
      classification: "supported" as const,
      metrics: undefined,
    }));
    const report: InvestigationReport = {
      schemaVersion: 1,
      id: `rpt-${date}-ask-investigation-${safeKey}`,
      incidentKey,
      playbook: "ask-investigation",
      trigger: {
        detectedAtUTC: now.toISOString(),
        detectorId: "ask-investigation",
        candidate: { host, gaps: stats.gaps.length, windowHours: stats.windowHours },
      },
      conclusion: {
        classification: stats.gaps.some((g) => g.abruptStop) ? "suspicious" : "informational",
        confidence: synthesis.confidence,
        summary: synthesis.verdict,
      },
      scope: {
        fromUTC: stats.windowFromUTC,
        toUTC: stats.windowToUTC,
        entities: [host],
      },
      timeline: stats.hourly.slice(-30).map((h) => ({
        ts: h.bucket,
        source: "homelab.syslog",
        description: `${h.total} lines`,
      })),
      observations: findings,
      hypotheses: [
        {
          name: "log silence analysis",
          verdict: findings[0] ?? {
            id: "f1",
            statement: "Inspection pending",
            evidence: [],
            classification: "unresolved",
          },
          alternativesTested: ["clean shutdown", "logging path failure", "normal quiet period"],
        },
      ],
      coverage: [
        {
          table: "homelab.syslog",
          windowRows: stats.linesInWindow,
          gaps: stats.gaps.map((g) => `silent ${g.hours}h from ${g.startUTC}`),
        },
      ],
      uncertainty: [
        "silence is ambiguous from telemetry: crash, clean stop and log-ship failure look similar",
        "root cause beyond the shipped logs is not captured",
      ],
      nextSteps: synthesis.nextSteps,
      charts: [
        {
          type: "time-series",
          title: `${host} log volume (lines per hour)`,
          x: "bucket",
          y: "total",
          missingDataPolicy: "gap",
          timeWindow: { fromUTC: stats.windowFromUTC, toUTC: stats.windowToUTC },
        },
      ],
      provenance: {
        queryIds: evidence.map((e) => e.id),
        modelCalls: synthesis.usedModel ? [{ model: "investigation-verdict", purpose: "verdict synthesis" }] : [],
      },
      createdAtUTC: now.toISOString(),
      version: 1,
      severity: stats.gaps.some((g) => g.abruptStop && !g.pipelineShaped) ? "high" : "low",
      mitreTag: null,
      preview: buildPreview("ask-investigation", {
        host,
        gapHours: stats.gaps[0]?.hours ?? 0,
        abrupt: stats.gaps.some((g) => g.abruptStop),
        pipeline: stats.gaps.some((g) => g.pipelineShaped),
      }),
    };
    await persistReport(env as Parameters<typeof persistReport>[0], report);
    void user;
  } catch {
    /* filing must never break the answer */
  }
}
