// Shared typed contracts for the Ask service, the governed query service,
// scenario assembly, and investigations. Shapes follow the plan
// (/Users/ian/.opencode/plan/basin-flowviz-next-evolution.md, section 4.2),
// amended: baseline is part of the plan; "comparison" and "scenario-timeline"
// are chart types; evidence IDs are deterministic.

export type ChartType =
  | "time-series"
  | "comparison"
  | "ranked-bars"
  | "heatmap"
  | "distribution"
  | "state-timeline"
  | "coverage-grid"
  | "scenario-timeline"
  | "evidence-table";

export type Archetype =
  | "timeseries-count"
  | "timeseries-metric"
  | "rank"
  | "latest-state"
  | "coverage"
  | "scenario"
  | "unsupported";

export type PrivacyClass = "public" | "sanitized" | "raw";

export interface CatalogueColumn {
  name: string;
  type: "string" | "float64" | "timestamp" | "json" | "integer";
  jsonPaths?: string[];
  note?: string;
}

export interface CatalogueTable {
  id: string; // "homelab.dns_queries"
  label: string;
  columns: CatalogueColumn[];
  // Which column to time-bound by default, and why (plan 2.3.7):
  // ingest: Basin arrival, always present; event: true event time if reliable;
  // observation: upstream receive time (Vector now()).
  queryTimeColumn: string;
  queryTimeBasis: "ingest" | "event" | "observation";
  grain: string;
  privacyClass: PrivacyClass;
  synonyms: string[];
  caveats: string[];
  status: "available" | "degraded" | "probe-gated" | "disabled";
  statusNote?: string;
  verified?: string[]; // verified query ids (see catalogue.questions)
}

export interface VerifiedQuery {
  id: string;
  question: string;
  archetype: Archetype;
  table: string;
  chart: ChartType;
  params?: Record<string, unknown>; // compiler inputs (see validate.ts)
  sql?: string; // literal SQL when params do not express it
  notes: string[];
  status: "available" | "probe-gated";
  verifiedAt: string;
  verifiedBy: string;
}

export interface EntityMapEntry {
  entityId: string;
  label: string;
  room?: string;
  unit?: string;
  kind?: "room-temp" | "outdoor" | "weather" | "other";
}

export interface Catalogue {
  version: number;
  generatedAt: string;
  timezone: string; // Australia/Perth for user-facing labels; queries are UTC
  tables: CatalogueTable[];
  questions: VerifiedQuery[];
  entityMaps: Record<string, EntityMapEntry[]>;
  // clientHash -> known identity. Salt-free SHA-256 of the client string as
  // captured at ingest; covers known static IPv4s only. IPv6 privacy clients
  // rotate and stay opaque (plan 2.3.8).
  clientHashIdentities: Record<string, string>;
  facts: string[]; // live-verified platform findings the planner must respect
}

// --- model output, server-validated (the model never writes SQL in MVP:
// the server compiles deterministically from the plan) ---
export interface PlanFilter {
  column: string;
  jsonPath?: string;
  op: "=" | "LIKE" | "ILIKE" | "IN";
  value: string | number | (string | number)[];
}

export interface QueryPlan {
  archetype: Archetype;
  table: string;
  fromUTC: string;
  toUTC: string;
  basis?: "ingest" | "event" | "observation";
  filters?: PlanFilter[];
  dimension?: { column: string; jsonPath?: string };
  series?: { column: string; jsonPath?: string };
  measure?: {
    expr: "count" | "approx_distinct" | "avg" | "max" | "min" | "sum";
    column?: string;
    jsonPath?: string;
  };
  grain?: "hour" | "day";
  limit?: number;
  entityPrefix?: string;
  chart?: {
    type: ChartType;
    x?: string;
    y?: string;
    series?: string;
    unit?: string;
    baseline?: boolean;
  };
  ambiguities?: string[];
  unsupportedReason?: string;
  verifiedQueryId?: string;
}

// --- compiled query ---
export interface CompiledQuery {
  sql: string;
  primaryTable: string;
  baselineSql?: string; // second validated query when baseline requested
}

// --- results ---
export interface QueryResult {
  requestId: string;
  schema: { name: string; type: string }[];
  rows: Record<string, unknown>[];
  metrics: { bytesScanned: number; filesScanned: number };
  truncation: { applied: boolean; reason?: string };
  freshness: {
    maxIngestTs?: string;
    maxEventTs?: string;
    completeness: "verified" | "partial" | "unknown";
  };
}

// --- chart spec (server-validated against the result schema) ---
export interface ChartSpec {
  type: ChartType;
  title: string;
  x?: string;
  y?: string;
  series?: string;
  unit?: string;
  baseline?: { fromUTC: string; toUTC: string };
  missingDataPolicy: "gap" | "zero";
  timeWindow: { fromUTC: string; toUTC: string };
}

// --- evidence ---
export interface EvidenceRecord {
  id: string; // evid_<requestId>_<sha256hex12>
  kind: "query" | "rows" | "coverage" | "baseline" | "scenario";
  sql: string;
  requestId: string;
  rowCount: number;
  truncated: boolean;
  snapshotKey?: string; // R2 object key
  createdAt: string;
}

// --- findings and reports ---
export interface Finding {
  id: string;
  statement: string;
  evidence: string[]; // evidence IDs; must be non-empty
  classification: "supported" | "refuted" | "unresolved";
  uncertainty?: string;
}

export interface InvestigationReport {
  schemaVersion: 1;
  id: string;
  incidentKey: string;
  playbook: string;
  trigger: {
    detectedAtUTC: string;
    detectorId: string;
    candidate: unknown;
  };
  conclusion: {
    classification: "suspicious" | "benign" | "inconclusive" | "informational";
    confidence: "low" | "medium" | "high";
    summary: string;
  };
  scope: { fromUTC: string; toUTC: string; entities: string[] };
  timeline: {
    ts: string;
    ingestTs?: string;
    source: string;
    description: string;
    evidenceId?: string;
  }[];
  observations: Finding[];
  hypotheses: { name: string; verdict: Finding; alternativesTested: string[] }[];
  coverage: {
    table: string;
    windowRows: number;
    freshness?: QueryResult["freshness"];
    gaps: string[];
  }[];
  uncertainty: string[];
  nextSteps: string[];
  charts: ChartSpec[];
  provenance: {
    queryIds: string[];
    modelCalls: { model: string; purpose: string; tokensIn?: number; tokensOut?: number }[];
  };
  createdAtUTC: string;
  version: number;
  supersedes?: string;
}

// --- ask response ---
export type AskState =
  | "answered"
  | "ambiguous"
  | "unsupported"
  | "empty"
  | "stale"
  | "truncated"
  | "failed"
  | "limited"
  | "model-unavailable"
  | "scenario";

export interface AskResponse {
  state: AskState;
  question: string;
  plan?: QueryPlan;
  answer?: string;
  numbers?: Record<string, number | string>;
  chart?: ChartSpec;
  chartData?: unknown[];
  baselineData?: unknown[];
  evidence?: EvidenceRecord[];
  ambiguities?: string[];
  notes: string[];
  freshness?: QueryResult["freshness"];
  scenarioTimeline?: unknown[]; // for state: "scenario"
}
