// Ask route handlers: /api/ask, /api/catalog, /api/evidence/:id/rows.
// The plan layer (compilePlan) is the only SQL source; results are typed,
// chart data is computed from rows (never from model prose), and every
// answer carries its evidence bundle.

import { renderForBrowser, matchVerifiedQuestion } from "../catalog/render";
import { compilePlan, validateChartAgainstSchema } from "../catalog/validate";
import type { AskResponse, QueryPlan, QueryResult, EvidenceRecord, ChartSpec, CompiledQuery } from "../catalog/types";
import { executeGoverned, snapshotEvidence, loadEvidenceRows, rateLimitAsk, QueryLimit, evidenceIdPattern } from "../query/service";
import { planQuestion, repairPlan, narrateAnswer, type PlanSession, type PlanCallResult } from "./planner";
import { assembleScenario } from "../investigate/scenario";
import type { ServiceEnv } from "../bindings";

export function userOf(req: Request): string {
  return (
    req.headers.get("Cf-Access-Authenticated-User-Email") ??
    req.headers.get("x-test-user") ??
    "local"
  );
}

function iso(x: unknown): string | null {
  if (typeof x !== "string") return null;
  const t = Date.parse(x);
  return Number.isFinite(t) ? new Date(t).toISOString() : x;
}

// Map result rows to chart data, computed server-side from the query result.
function chartDataFor(spec: ChartSpec, rows: Record<string, unknown>[]): unknown[] {
  switch (spec.type) {
    case "time-series":
    case "comparison":
      return rows.map((r) => ({
        x: iso(r.bucket) ?? String(r.bucket ?? ""),
        y: Number(r.c ?? 0),
        series: r.series !== undefined && r.series !== null ? String(r.series) : undefined,
      }));
    case "ranked-bars":
      return rows.map((r) => ({
        name: String(
          r.dim ?? r.domain ?? r.entity_id ?? r.host ?? r.langs ?? r.ScriptName ?? "",
        ),
        value: Number(r.m ?? r.c ?? r.avg_c ?? 0),
      }));
    case "state-timeline":
      return rows.map((r) => ({
        entity_id: String(r.entity_id ?? ""),
        state: String(r.state ?? ""),
        ts: iso(r.ts) ?? String(r.ts ?? ""),
      }));
    case "coverage-grid":
      return rows.map((r) => ({
        t: String(r.t ?? ""),
        hour: iso(r.hour) ?? String(r.hour ?? ""),
        c: Number(r.c ?? 0),
      }));
    default:
      return rows.slice(0, 100);
  }
}

async function runPlan(
  env: ServiceEnv,
  question: string,
  session: PlanSession | undefined,
): Promise<
  | { kind: "compiled"; plan: QueryPlan; compiled: CompiledQuery; chart: ChartSpec; notes: string[] }
  | { kind: "ambiguous"; ambiguities: string[]; note?: string }
  | { kind: "unsupported"; note: string }
  | { kind: "failed"; error: string }
  | { kind: "model-unavailable"; error: string }
> {
  const first = await planQuestion(env, question, session);
  type Attempt =
    | { kind: "compiled"; plan: QueryPlan; compiled: CompiledQuery; chart: ChartSpec; notes: string[] }
    | { kind: "ambiguous"; ambiguities: string[]; note?: string }
    | { kind: "unsupported"; note: string }
    | { kind: "failed"; error: string }
    | { kind: "model-unavailable"; error: string };
  const attempt = async (call: PlanCallResult, repairOf?: QueryPlan): Promise<Attempt> => {
    switch (call.state) {
      case "model-unavailable": {
        // Fallback: verified-question match, else an honest unavailable state.
        const v = matchVerifiedQuestion(question);
        if (v && call.plan === undefined) {
          const plan: QueryPlan = {
            archetype: v.archetype === "coverage" ? "coverage" : v.archetype,
            table: v.table,
            fromUTC: "",
            toUTC: "",
            verifiedQueryId: v.id,
          };
          const out = compilePlan(plan, question, new Date());
          if (out.ok) return { kind: "compiled", plan, compiled: out.compiled, chart: out.chart, notes: [...out.notes, "model unavailable: answered from a verified question"] };
          return { kind: "model-unavailable", error: call.error ?? "model unavailable" };
        }
        return { kind: "model-unavailable", error: call.error ?? "model unavailable" };
      }
      case "unsupported":
        return { kind: "unsupported", note: call.note ?? "not supported by available telemetry" };
      case "ambiguous":
        return { kind: "ambiguous", ambiguities: call.plan?.ambiguities ?? [], note: call.note };
      case "answered": {
        const plan = call.plan!;
        if (plan.archetype === "scenario") {
          return { kind: "unsupported", note: "scenario requests are handled by the assembly service" };
        }
        const out = compilePlan(plan, question, new Date());
        if (out.ok) return { kind: "compiled", plan, compiled: out.compiled, chart: out.chart, notes: out.notes };
        if ("error" in out) {
          // One bounded repair round for model-planned queries only.
          if (!repairOf && !plan.verifiedQueryId) {
            const repair = await repairPlan(env, question, session, plan, out.error);
            return attempt(repair, plan);
          }
          return { kind: "failed", error: out.error };
        }
        if ("unsupported" in out) return { kind: "unsupported", note: out.unsupported };
        return { kind: "failed", error: "plan validation failed" };
      }
      default:
        return { kind: "failed", error: "unexpected planner state" };
    }
  };
  return attempt(first);
}

export async function handleAsk(env: ServiceEnv, req: Request): Promise<Response> {
  const user = userOf(req);
  let body: { question?: unknown; session?: unknown };
  try {
    body = await req.json();
  } catch {
    return Response.json({ state: "failed", notes: ["invalid JSON body"] }, { status: 400 });
  }
  const question = typeof body.question === "string" ? body.question.trim().slice(0, 400) : "";
  if (!question) {
    return Response.json({ state: "failed", notes: ["expected {\"question\": string}"] }, { status: 400 });
  }
  const session =
    body.session && typeof body.session === "object" ? (body.session as PlanSession) : undefined;

  try {
    await rateLimitAsk(env, user);
  } catch (e) {
    if (e instanceof QueryLimit) {
      return Response.json(
        {
          state: "limited",
          question,
          notes: [e.reason === "rate" ? "too many questions per minute" : "daily scan budget exhausted"],
        },
        { status: 429 },
      );
    }
    throw e;
  }

  // Scenario archetype: multi-source assembly instead of a single query.
  const sessionScopedScenario =
    session?.tableScope && session.fromUTC && session.toUTC && /scenario|everything|happened/i.test(question);

  const out = await runPlan(env, question, session);
  if (out.kind === "model-unavailable") {
    return Response.json(
      {
        state: "model-unavailable",
        question,
        notes: [
          "The planner model is unavailable or returned an unusable plan.",
          out.error ? `detail: ${out.error}` : "",
          "Verified questions still work from the chips.",
        ].filter(Boolean),
      },
      { headers: { "Cache-Control": "no-store" } },
    );
  }
  if (out.kind === "ambiguous") {
    return Response.json(
      {
        state: "ambiguous",
        question,
        ambiguities: out.ambiguities,
        notes: ["Pick or rephrase one interpretation."],
      },
      { headers: { "Cache-Control": "no-store" } },
    );
  }
  if (out.kind === "unsupported") {
    return Response.json(
      {
        state: "unsupported",
        question,
        notes: [out.note],
      },
      { headers: { "Cache-Control": "no-store" } },
    );
  }
  if (out.kind === "failed") {
    return Response.json(
      { state: "failed", question, notes: [out.error] },
      { headers: { "Cache-Control": "no-store" } },
    );
  }

  // Scenario assembly path (archetype scenario or scoped session request).
  if (out.plan.archetype === "scenario" || sessionScopedScenario) {
    const from = out.chart.timeWindow.fromUTC;
    const to = out.chart.timeWindow.toUTC;
    const scenario = await assembleScenario(env, user, { fromUTC: from, toUTC: to });
    return Response.json(
      {
        state: "scenario",
        question,
        scenarioTimeline: scenario.events,
        evidence: scenario.evidence,
        notes: [
          "Fused timeline across sources, aligned on ingest time; event time can differ per source.",
          ...scenario.coverage.map((c) => `${c.table}: ${c.windowRows} row(s) in window${c.note ? ` (${c.note})` : ""}`),
        ],
        chart: {
          type: "scenario-timeline",
          title: question,
          missingDataPolicy: "gap",
          timeWindow: { fromUTC: from, toUTC: to },
        },
      },
      { headers: { "Cache-Control": "no-store" } },
    );
  }

  // Governed execution of the compiled plan.
  const primary = await executeGoverned(env, user, out.compiled.sql, {
    primaryTable: out.compiled.primaryTable,
  });
  if (!primary.ok) {
    return Response.json(
      { state: "failed", question, notes: [primary.error], plan: out.plan },
      { headers: { "Cache-Control": "no-store" } },
    );
  }
  const result: QueryResult = primary.result;

  // Baseline comparison: a second validated query, same shape.
  let baselineData: unknown[] | undefined;
  let baselineEvidence: EvidenceRecord | undefined;
  if (out.compiled.baselineSql) {
    const b = await executeGoverned(env, user, out.compiled.baselineSql, {
      primaryTable: out.compiled.primaryTable,
    });
    if (b.ok) {
      baselineData = chartDataFor(out.chart, b.result.rows);
      baselineEvidence = await snapshotEvidence(env, {
        sql: out.compiled.baselineSql,
        result: b.result,
        kind: "baseline",
      });
    }
  }

  // Chart validation against the actual result schema.
  const chartCheck = validateChartAgainstSchema(out.chart, result.schema);
  const chart: ChartSpec = chartCheck.ok ? out.chart : { ...out.chart, x: undefined, y: undefined, series: undefined };

  const evidence: EvidenceRecord[] = [
    await snapshotEvidence(env, { sql: out.compiled.sql, result, kind: "query" }),
    ...(baselineEvidence ? [baselineEvidence] : []),
  ];

  const windowHours = (
    (Date.parse(chart.timeWindow.toUTC) - Date.parse(chart.timeWindow.fromUTC)) /
    3600_000
  ).toFixed(1);

  const stats: Record<string, number | string> = {
    rows: result.rows.length,
    bytesScanned: result.metrics.bytesScanned,
    filesScanned: result.metrics.filesScanned,
    windowHours: Number(windowHours),
    truncated: result.truncation.applied ? "yes" : "no",
    meaning: out.notes.slice(0, 3).join(" | ").slice(0, 400),
  };
  const firstRow = result.rows[0];
  if (firstRow?.dim !== undefined) stats.top = `${String(firstRow.dim)} (${firstRow.m})`;

  const narration = await narrateAnswer(env, question, stats, result.rows);
  if (!narration.usedModel) {
    out.notes.push("model unavailable: answer line generated from the numbers only");
  }

  const state: AskResponse["state"] =
    result.rows.length === 0 ? "empty" : result.truncation.applied ? "truncated" : "answered";

  return Response.json(
    {
      state,
      question,
      plan: out.plan,
      answer: narration.answer,
      numbers: stats,
      chart,
      chartData: chartDataFor(chart, result.rows),
      baselineData,
      evidence,
      freshness: result.freshness,
      notes: out.notes,
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}

export async function handleCatalog(req: Request): Promise<Response> {
  const body = renderForBrowser();
  const json = JSON.stringify(body);
  const etag = `"c${body.version}-${body.generatedAt}"`;
  if (req.headers.get("If-None-Match") === etag) {
    return new Response(null, { status: 304, headers: { ETag: etag } });
  }
  return new Response(json, {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      Etag: etag,
    },
  });
}

export async function handleEvidenceRows(
  env: ServiceEnv,
  id: string,
  url: URL,
): Promise<Response> {
  if (!evidenceIdPattern().test(id)) {
    return Response.json({ error: "invalid evidence id" }, { status: 400 });
  }
  const offset = Number(url.searchParams.get("offset") ?? "0");
  const limit = Number(url.searchParams.get("limit") ?? "50");
  const data = await loadEvidenceRows(env, id, offset, limit);
  if (!data) {
    return Response.json({ error: "evidence not found" }, { status: 404 });
  }
  return Response.json(data, { headers: { "Cache-Control": "no-store" } });
}
