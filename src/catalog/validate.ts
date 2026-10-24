// Plan validation and deterministic SQL compilation.
//
// MVP safety decision (plan section 5.1, constrained compilation): the model
// NEVER writes SQL. It emits a typed QueryPlan; this module is the only place
// SQL is generated for Ask, and every produced statement still passes through
// the shared lexical guardrails (src/sql.ts sanitizeSql) plus an EXPLAIN
// preflight at execution time. Model-proposed plan.sql is ignored.
//
// Era-safe JSON: dns_queries fields changed encoding mid-day on 2026-10-24
// (~11:30Z: direct JSON object after, double-encoded string before), so every
// fields extraction uses COALESCE(direct, nested). host_metrics and unifi
// remain double-encoded and oversized (regexp fallback is catalogue-noted but
// those tables are probe-gated for MVP).

import { catalog, getTable, getQuestion } from "./render";
import { sqlLit } from "../sql";
import type {
  QueryPlan,
  CompiledQuery,
  PlanFilter,
  ChartSpec,
  ChartType,
} from "./types";

const MAX_WINDOW_DAYS = 30;
const LATEST_STATE_MAX_DAYS = 7;
const DEFAULT_HOURS = 24;

export type PlanOutcome =
  | { ok: true; compiled: CompiledQuery; chart: ChartSpec; notes: string[]; fromUTC: string; toUTC: string }
  | { ok: false; error: string }
  | { ok: false; ambiguous: string[] }
  | { ok: false; unsupported: string };

interface NormalizedWindow {
  fromUTC: string;
  toUTC: string;
}

// Era-safe expression for a JSON path on a fields column.
function jsonExpr(tableId: string, path: string): string | null {
  const t = getTable(tableId);
  if (!t) return null;
  const col = t.columns.find((c) => c.jsonPaths && c.jsonPaths.includes(path));
  if (!col) return null;
  const direct = `json_get_str(${col.name}, ${sqlLit(path)})`;
  const nested = `json_get_str(json_get_str(${col.name}), ${sqlLit(path)})`;
  // dns_queries rows exist in both encodings across 2026-10-24: cover both.
  if (tableId === "homelab.dns_queries") return `COALESCE(${direct}, ${nested})`;
  return nested;
}

function columnExpr(tableId: string, ref: { column: string; jsonPath?: string }): string | null {
  const t = getTable(tableId);
  if (!t) return null;
  if (ref.jsonPath) return jsonExpr(tableId, ref.jsonPath);
  return t.columns.some((c) => c.name === ref.column) ? ref.column : null;
}

function measureExpr(
  tableId: string,
  measure: NonNullable<QueryPlan["measure"]>,
): string | null {
  if (measure.expr === "count") return "COUNT(*)";
  let colExpr: string | null = null;
  if (measure.jsonPath) colExpr = jsonExpr(tableId, measure.jsonPath);
  else if (measure.column) colExpr = columnExpr(tableId, { column: measure.column });
  if (!colExpr) return null;
  switch (measure.expr) {
    case "approx_distinct":
      return `approx_distinct(${colExpr})`;
    case "avg":
      return `AVG(${colExpr})`;
    case "max":
      return `MAX(${colExpr})`;
    case "min":
      return `MIN(${colExpr})`;
    case "sum":
      return `SUM(${colExpr})`;
    default:
      return null;
  }
}

function filterSql(tableId: string, filters: PlanFilter[]): string | null {
  const parts: string[] = [];
  for (const f of filters ?? []) {
    let expr: string | null;
    if (f.jsonPath) {
      expr = jsonExpr(tableId, f.jsonPath);
    } else {
      const t = getTable(tableId);
      if (!t || !t.columns.some((c) => c.name === f.column)) return null;
      expr = f.column;
    }
    if (!expr) return null;
    switch (f.op) {
      case "=": {
        if (typeof f.value !== "string" && typeof f.value !== "number") return null;
        parts.push(`${expr} = ${typeof f.value === "number" ? f.value : sqlLit(f.value)}`);
        break;
      }
      case "LIKE":
      case "ILIKE": {
        if (typeof f.value !== "string") return null;
        parts.push(`${expr} ${f.op} ${sqlLit(f.value)}`);
        break;
      }
      case "IN": {
        if (!Array.isArray(f.value) || !f.value.length || f.value.length > 20) return null;
        const vals = f.value.map((v) =>
          typeof v === "number" ? String(v) : sqlLit(String(v)),
        );
        parts.push(`${expr} IN (${vals.join(", ")})`);
        break;
      }
      default:
        return null;
    }
  }
  return parts.length ? parts.join(" AND ") : "";
}

function resolveWindow(plan: Partial<QueryPlan>, now: Date): NormalizedWindow | null {
  const toMs = plan.toUTC ? Date.parse(plan.toUTC) : now.getTime();
  const fromMs = plan.fromUTC ? Date.parse(plan.fromUTC) : toMs - DEFAULT_HOURS * 3600_000;
  if (!Number.isFinite(toMs) || !Number.isFinite(fromMs)) return null;
  if (fromMs >= toMs) return null;
  if (toMs - fromMs > MAX_WINDOW_DAYS * 86400_000) return null;
  if (toMs > now.getTime() + 5 * 60_000) return null;
  return {
    fromUTC: new Date(fromMs).toISOString(),
    toUTC: new Date(toMs).toISOString(),
  };
}

function timePred(tableId: string, w: NormalizedWindow): string | null {
  const t = getTable(tableId);
  if (!t) return null;
  const col = t.queryTimeColumn;
  if (col === "__ingest_ts" || t.columns.some((c) => c.name === col)) {
    return `${col} >= ${sqlLit(w.fromUTC)} AND ${col} < ${sqlLit(w.toUTC)}`;
  }
  return null;
}

function defaultChart(
  type: ChartType,
  question: string,
  w: NormalizedWindow,
  x?: string,
  y?: string,
  series?: string,
  baseline?: { fromUTC: string; toUTC: string },
): ChartSpec {
  return {
    type,
    title: question,
    x,
    y,
    series,
    unit: undefined,
    baseline,
    missingDataPolicy: "gap",
    timeWindow: { fromUTC: w.fromUTC, toUTC: w.toUTC },
  };
}

function fillLiteralSql(
  sql: string,
  w: NormalizedWindow,
): string {
  return sql.replaceAll("{FROM}", sqlLit(w.fromUTC)).replaceAll("{TO}", sqlLit(w.toUTC));
}

// Compile a normalized plan (from the model or built from a verified question).
export function compilePlan(plan: QueryPlan, question: string, now: Date): PlanOutcome {
  const notes: string[] = [];
  const w = resolveWindow(plan, now);
  if (!w) return { ok: false, error: "invalid or missing time window" };

  // Verified-question shortcut: the catalogue carries either literal SQL or
  // compiler params; both are owner-checked and produce bounded SQL. An
  // unknown id falls through to archetype compilation instead of failing.
  if (plan.verifiedQueryId) {
    const v = getQuestion(plan.verifiedQueryId);
    if (v) {
      if (v.status !== "available") {
        return { ok: false, unsupported: v.notes.join(" ") || "verified question is not available" };
      }
      const vw = resolveWindow(
        {
          ...(v.params?.windowHours
            ? { fromUTC: new Date(now.getTime() - (v.params.windowHours as number) * 3600_000).toISOString(), toUTC: now.toISOString() }
            : {}),
          ...plan,
        } as QueryPlan,
        now,
      );
      if (!vw) return { ok: false, error: "invalid window for verified question" };
      let sql: string;
      if (v.sql) {
        sql = fillLiteralSql(v.sql, vw);
      } else {
        const built = buildFromParams(v, vw, now);
        if ("error" in built) return { ok: false, error: built.error };
        sql = built.sql;
      }
      let baselineSql: string | undefined;
      let baseline: ChartSpec["baseline"];
      if ((v.params?.baseline as boolean) || plan.chart?.baseline) {
        const spanMs = Date.parse(vw.toUTC) - Date.parse(vw.fromUTC);
        baseline = {
          fromUTC: new Date(Date.parse(vw.fromUTC) - spanMs).toISOString(),
          toUTC: vw.fromUTC,
        };
        if (v.sql) {
          baselineSql = fillLiteralSql(v.sql, baseline);
        } else {
          const built = buildFromParams(v, baseline, now);
          if ("error" in built) return { ok: false, error: built.error };
          baselineSql = built.sql;
        }
      }
      const chart = defaultChart(v.chart, question || v.question, vw, undefined, undefined, undefined, baseline);
      return {
        ok: true,
        compiled: { sql, primaryTable: v.table, baselineSql },
        chart,
        notes: v.notes,
        fromUTC: vw.fromUTC,
        toUTC: vw.toUTC,
      };
    }
  }

  if (plan.archetype === "unsupported") {
    return {
      ok: false,
      unsupported: plan.unsupportedReason ?? "the requested analysis is not supported by the available telemetry",
    };
  }
  if (plan.archetype === "scenario") {
    // The scenario service handles execution; compilation is not needed.
    return { ok: false, error: "scenario archetype is handled by the assembly service" };
  }

  const tableId = plan.table;
  const table = getTable(tableId);
  if (!table) return { ok: false, error: `unknown table ${tableId}` };
  if (table.status !== "available") {
    return { ok: false, unsupported: table.statusNote ?? `table ${tableId} is not available (${table.status})` };
  }

  const tp = timePred(tableId, w);
  if (!tp) return { ok: false, error: "table has no usable time column" };
  const fs = filterSql(tableId, plan.filters ?? []);
  if (fs === null) return { ok: false, error: "invalid filter (unknown column or json path)" };
  const where = fs ? `${tp} AND ${fs}` : tp;
  const limit = Math.min(Math.max(plan.limit ?? 15, 1), 200);

  switch (plan.archetype) {
    case "rank": {
      if (!plan.dimension) return { ok: false, error: "rank archetype needs a dimension" };
      const dimExpr = columnExpr(tableId, plan.dimension);
      if (!dimExpr) return { ok: false, error: "rank dimension is not an allowlisted column" };
      const mExpr = measureExpr(tableId, plan.measure ?? { expr: "count" });
      if (!mExpr) return { ok: false, error: "measure is not allowlisted" };
      const sql =
        `SELECT ${dimExpr} AS dim, ${mExpr} AS m FROM ${tableId} ` +
        `WHERE ${where} GROUP BY dim ORDER BY m DESC LIMIT ${limit}`;
      const chart = defaultChart("ranked-bars", question, w, "dim", "m");
      return { ok: true, compiled: { sql, primaryTable: tableId }, chart, notes: table.caveats, fromUTC: w.fromUTC, toUTC: w.toUTC };
    }
    case "timeseries-count": {
      const grain = plan.grain === "day" ? "day" : "hour";
      const tcol = table.queryTimeColumn;
      const seriesExpr = plan.series ? columnExpr(tableId, plan.series) : null;
      if (plan.series && !seriesExpr) return { ok: false, error: "series is not an allowlisted column" };
      const groupCols = `date_trunc('${grain}', ${tcol})` + (seriesExpr ? `, ${seriesExpr}` : "");
      const sql =
        `SELECT date_trunc('${grain}', ${tcol}) AS bucket` +
        (seriesExpr ? `, ${seriesExpr} AS series` : "") +
        `, COUNT(*) AS c FROM ${tableId} WHERE ${where} ` +
        `GROUP BY ${groupCols} ORDER BY bucket LIMIT 2000`;
      let baselineSql: string | undefined;
      let baseline: ChartSpec["baseline"];
      if (plan.chart?.baseline) {
        const spanMs = Date.parse(w.toUTC) - Date.parse(w.fromUTC);
        const bFrom = new Date(Date.parse(w.fromUTC) - spanMs).toISOString();
        const bTo = w.fromUTC;
        const bWhere = where.replaceAll(sqlLit(w.fromUTC), sqlLit(bFrom)).replaceAll(sqlLit(w.toUTC), sqlLit(bTo));
        baselineSql =
          `SELECT date_trunc('${grain}', ${tcol}) AS bucket` +
          (seriesExpr ? `, ${seriesExpr} AS series` : "") +
          `, COUNT(*) AS c FROM ${tableId} WHERE ${bWhere} ` +
          `GROUP BY ${groupCols} ORDER BY bucket LIMIT 2000`;
        baseline = { fromUTC: bFrom, toUTC: bTo };
      }
      const chartType: ChartType = baseline ? "comparison" : "time-series";
      const chart = defaultChart(chartType, question, w, "bucket", "c", seriesExpr ? "series" : undefined, baseline);
      return { ok: true, compiled: { sql, primaryTable: tableId, baselineSql }, chart, notes: table.caveats, fromUTC: w.fromUTC, toUTC: w.toUTC };
    }
    case "timeseries-metric": {
      if (tableId !== "ha.ha_sensor_readings") {
        return { ok: false, error: "timeseries-metric is limited to ha.ha_sensor_readings in MVP" };
      }
      const hasEntity = (plan.filters ?? []).some(
        (f) => f.column === "entity_id" && (f.op === "=" || f.op === "IN"),
      );
      if (!hasEntity) return { ok: false, error: "metric archetype needs an entity_id filter" };
      const grain = plan.grain === "day" ? "day" : "hour";
      const sql =
        `SELECT date_trunc('${grain}', ts) AS bucket, ROUND(AVG(value), 2) AS avg_v, ` +
        `MAX(value) AS max_v, MIN(value) AS min_v, COUNT(*) AS n ` +
        `FROM ha.ha_sensor_readings WHERE ${where} ` +
        `GROUP BY date_trunc('${grain}', ts) ORDER BY bucket LIMIT 2000`;
      const chart = defaultChart("time-series", question, w, "bucket", "avg_v");
      return { ok: true, compiled: { sql, primaryTable: tableId }, chart, notes: table.caveats, fromUTC: w.fromUTC, toUTC: w.toUTC };
    }
    case "latest-state": {
      if (tableId !== "ha.ha_state_changes") {
        return { ok: false, error: "latest-state is limited to ha.ha_state_changes" };
      }
      const prefix = plan.entityPrefix ?? "";
      if (!/^[a-z_]+\.$/.test(prefix)) return { ok: false, error: "latest-state needs a HA domain prefix like 'light.'" };
      if (Date.parse(w.toUTC) - Date.parse(w.fromUTC) > LATEST_STATE_MAX_DAYS * 86400_000) {
        return { ok: false, error: `latest-state window is capped at ${LATEST_STATE_MAX_DAYS} days` };
      }
      const sql =
        `SELECT entity_id, state, ts FROM ha.ha_state_changes ` +
        `WHERE entity_id LIKE ${sqlLit(prefix + "%")} AND ts >= ${sqlLit(w.fromUTC)} AND ts < ${sqlLit(w.toUTC)} ` +
        `QUALIFY ROW_NUMBER() OVER (PARTITION BY entity_id ORDER BY ts DESC) = 1 ` +
        `ORDER BY entity_id LIMIT 200`;
      const chart = defaultChart("state-timeline", question, w, "entity_id", "state");
      return { ok: true, compiled: { sql, primaryTable: tableId }, chart, notes: table.caveats, fromUTC: w.fromUTC, toUTC: w.toUTC };
    }
    case "coverage": {
      const v = getQuestion("q-coverage");
      if (!v || !v.sql) return { ok: false, error: "coverage compilation is not available" };
      const sql = fillLiteralSql(v.sql, w);
      const chart = defaultChart("coverage-grid", question, w, "hour", "c", "t");
      return { ok: true, compiled: { sql, primaryTable: "homelab.syslog" }, chart, notes: v.notes, fromUTC: w.fromUTC, toUTC: w.toUTC };
    }
    default:
      return { ok: false, error: `archetype ${plan.archetype} is not compilable` };
  }
}

// Build a verified question's params into SQL through the same allowlist,
// routing by the verified question's archetype.
function buildFromParams(
  v: { archetype: string; table: string; params?: Record<string, unknown> },
  w: NormalizedWindow,
  now: Date,
): { sql: string } | { error: string } {
  const p = (v.params ?? {}) as {
    dimension?: { column: string; jsonPath?: string };
    measure?: { expr: string; column?: string };
    limit?: number;
    entityPrefix?: string;
    grain?: "hour" | "day";
  };
  const base = { table: v.table, fromUTC: w.fromUTC, toUTC: w.toUTC };
  let plan: QueryPlan;
  switch (v.archetype) {
    case "rank":
      plan = {
        archetype: "rank",
        ...base,
        dimension: p.dimension,
        measure: p.measure as QueryPlan["measure"],
        limit: p.limit,
      };
      break;
    case "timeseries-count":
      plan = {
        archetype: "timeseries-count",
        ...base,
        grain: p.grain,
      };
      break;
    case "latest-state":
      plan = {
        archetype: "latest-state",
        ...base,
        entityPrefix: p.entityPrefix,
      };
      break;
    default:
      return { error: `verified question archetype ${v.archetype} has no param compiler` };
  }
  const out = compilePlan(plan, "verified", now);
  if (!out.ok) return { error: "error" in out ? out.error : "verified question failed validation" };
  return { sql: out.compiled.sql };
}

// Validate a chart spec against an actual result schema (plan 4.2 rules):
// every referenced column must exist; no expressions, no URLs, no code.
export function validateChartAgainstSchema(
  chart: ChartSpec,
  schema: { name: string }[],
): { ok: true } | { ok: false; error: string } {
  const names = new Set(schema.map((c) => c.name));
  for (const ref of [chart.x, chart.y, chart.series]) {
    if (ref === undefined) continue;
    if (!/^[a-z_][a-z0-9_]*$/i.test(ref)) return { ok: false, error: `invalid chart column ${ref}` };
    if (!names.has(ref)) return { ok: false, error: `chart column ${ref} is not in the result` };
  }
  if (chart.title.length > 200) chart.title = chart.title.slice(0, 200);
  return { ok: true };
}

export const ALLOWED_ARCHETYPES = [
  "timeseries-count",
  "timeseries-metric",
  "rank",
  "latest-state",
  "coverage",
  "scenario",
  "unsupported",
] as const;

export function catalogueSummary() {
  return {
    version: catalog.version,
    tables: catalog.tables.length,
    questions: catalog.questions.length,
  };
}
