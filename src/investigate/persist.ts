// Report persistence (run 9): shared by the investigation Workflow and
// the Ask investigate loop. Kept in its own module so the loop can be
// unit-tested without pulling in cloudflare:workers.
//
// Reports are append-only: the full JSON goes to R2 under
// reports/{id}/v{n}.json; the D1 row is an upsert pointer that also
// carries the inbox preview (run 8).

import type { SchedulerEnv } from "./detectors";
import type { InvestigationReport } from "../catalog/types";

export async function persistReport(
  env: SchedulerEnv,
  report: InvestigationReport,
): Promise<void> {
  const key = `reports/${report.id}/v${report.version}.json`;
  if (env.REPORTS_R2) {
    await env.REPORTS_R2.put(key, JSON.stringify(report), {
      httpMetadata: { contentType: "application/json" },
    });
  }
  if (env.REPORTS_D1) {
    await env.REPORTS_D1.prepare(
      "INSERT INTO reports (id, incident_key, playbook, status, classification, confidence, severity, mitre_tag, latest_version, r2_key, preview, created_at, updated_at, last_seen_at) " +
        "VALUES (?1, ?2, ?3, 'open', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11, ?11) " +
        "ON CONFLICT (id) DO UPDATE SET latest_version = ?8, classification = ?4, confidence = ?5, " +
        "severity = ?6, mitre_tag = ?7, preview = ?10, updated_at = ?11",
    )
      .bind(
        report.id,
        report.incidentKey,
        report.playbook,
        report.conclusion.classification,
        report.conclusion.confidence,
        report.severity ?? "medium",
        report.mitreTag ?? null,
        report.version,
        key,
        report.preview ?? null,
        report.createdAtUTC,
      )
      .run();
  }
}
