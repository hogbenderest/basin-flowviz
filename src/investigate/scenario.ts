// Scenario assembly (plan 7.9): one fused, budget-bounded timeline across
// sources. The only universal join axis is time; identity is resolved with
// the curated client-hash map and each entry links to its evidence.

import { executeGoverned, snapshotEvidence } from "../query/service";
import { catalog } from "../catalog/render";
import type { EvidenceRecord, QueryResult } from "../catalog/types";
import type { ServiceEnv } from "../bindings";

const DEFAULT_SOURCES = [
  "homelab.syslog",
  "homelab.dns_queries",
  "ha.ha_state_changes",
  "cfwork.workers_trace_events",
] as const;

export interface ScenarioEvent {
  ts: string;
  ingestTs?: string;
  source: string;
  kind: string;
  actor?: string;
  description: string;
  evidenceId?: string;
}

export interface ScenarioResult {
  events: ScenarioEvent[];
  evidence: EvidenceRecord[];
  coverage: { table: string; windowRows: number; note?: string }[];
  window: { fromUTC: string; toUTC: string };
}

interface SourceDef {
  id: string;
  sql: (from: string, to: string) => string;
  kind: string;
  normalize: (row: Record<string, unknown>) => ScenarioEvent;
}

// All extraction uses the era-safe COALESCE form for dns fields (encoding
// changed mid-day 2026-10-24).
const SOURCES: SourceDef[] = [
  {
    id: "homelab.syslog",
    kind: "log",
    sql: (f, t) =>
      `SELECT host, ts, __ingest_ts, substr(message, 1, 180) AS message FROM homelab.syslog ` +
      `WHERE __ingest_ts >= '${f}' AND __ingest_ts < '${t}' ` +
      `ORDER BY __ingest_ts DESC LIMIT 120`,
    normalize: (r) => ({
      ts: String(r.ts ?? ""),
      ingestTs: String(r.__ingest_ts ?? ""),
      source: "syslog",
      kind: "log",
      actor: r.host ? String(r.host) : undefined,
      description: String(r.message ?? ""),
    }),
  },
  {
    id: "homelab.dns_queries",
    kind: "dns",
    sql: (f, t) =>
      `SELECT ts, __ingest_ts, ` +
      `COALESCE(json_get_str(fields, 'domain'), json_get_str(json_get_str(fields), 'domain')) AS domain, ` +
      `COALESCE(json_get_str(fields, 'client_hash'), json_get_str(json_get_str(fields), 'client_hash')) AS client_hash, ` +
      `COALESCE(json_get_str(fields, 'query_type'), json_get_str(json_get_str(fields), 'query_type')) AS query_type ` +
      `FROM homelab.dns_queries WHERE __ingest_ts >= '${f}' AND __ingest_ts < '${t}' ` +
      `ORDER BY __ingest_ts DESC LIMIT 120`,
    normalize: (r) => {
      const hash = r.client_hash ? String(r.client_hash) : undefined;
      return {
        ts: String(r.ts ?? ""),
        ingestTs: String(r.__ingest_ts ?? ""),
        source: "dns",
        kind: "dns query",
        actor: hash ? (catalog.clientHashIdentities[hash] ?? hash.slice(0, 8) + "...") : "unknown",
        description: `${r.query_type ?? "?"} ${r.domain ?? "?"}`,
      };
    },
  },
  {
    id: "ha.ha_state_changes",
    kind: "ha",
    sql: (f, t) =>
      `SELECT entity_id, state, ts, __ingest_ts FROM ha.ha_state_changes ` +
      `WHERE __ingest_ts >= '${f}' AND __ingest_ts < '${t}' ` +
      `ORDER BY __ingest_ts DESC LIMIT 120`,
    normalize: (r) => ({
      ts: String(r.ts ?? ""),
      ingestTs: String(r.__ingest_ts ?? ""),
      source: "ha",
      kind: "state",
      actor: r.entity_id ? String(r.entity_id) : undefined,
      description: `-> ${String(r.state ?? "?")}`,
    }),
  },
  {
    id: "cfwork.workers_trace_events",
    kind: "worker",
    sql: (f, t) =>
      `SELECT ScriptName, Outcome, __ingest_ts, substr(Event, 1, 120) AS event ` +
      `FROM cfwork.workers_trace_events ` +
      `WHERE __ingest_ts >= '${f}' AND __ingest_ts < '${t}' AND (ScriptName IS NULL OR ScriptName != 'basin-flowviz') ` +
      `ORDER BY __ingest_ts DESC LIMIT 120`,
    normalize: (r) => ({
      ts: String(r.__ingest_ts ?? ""),
      ingestTs: String(r.__ingest_ts ?? ""),
      source: "worker",
      kind: "trace",
      actor: r.ScriptName ? String(r.ScriptName) : undefined,
      description: `${String(r.Outcome ?? "?")}${r.event ? ": " + String(r.event) : ""}`,
    }),
  },
];

export async function assembleScenario(
  env: ServiceEnv,
  user: string,
  window: { fromUTC: string; toUTC: string },
  tables?: string[],
): Promise<ScenarioResult> {
  const selected = SOURCES.filter(
    (s) => !tables || !tables.length || tables.includes(s.id),
  ).slice(0, 6);
  const events: ScenarioEvent[] = [];
  const evidence: EvidenceRecord[] = [];
  const coverage: ScenarioResult["coverage"] = [];

  for (const src of selected) {
    const sql = src.sql(window.fromUTC, window.toUTC);
    const out = await executeGoverned(env, user, sql, {
      primaryTable: src.id,
      skipExplain: true,
    });
    if (!out.ok) {
      coverage.push({ table: src.id, windowRows: 0, note: `query failed: ${out.error}` });
      continue;
    }
    const result: QueryResult = out.result;
    const rec = await snapshotEvidence(env, { sql, result, kind: "scenario" });
    evidence.push(rec);
    for (const row of result.rows) {
      const ev = src.normalize(row);
      ev.evidenceId = rec.id;
      events.push(ev);
    }
    coverage.push({ table: src.id, windowRows: result.rows.length });
  }

  events.sort((a, b) => String(b.ingestTs ?? b.ts).localeCompare(String(a.ingestTs ?? a.ts)));
  return {
    events: events.slice(0, 300),
    evidence,
    coverage,
    window,
  };
}

export const scenarioSources = DEFAULT_SOURCES;
