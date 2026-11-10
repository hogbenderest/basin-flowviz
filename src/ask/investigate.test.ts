// Run 9 tests: entity resolution, gap detection, the distress taxonomy,
// the deterministic verdict, log-timeline compilation and the new
// previews. The HTPC incident (abrupt stop 2026-11-08T16:29Z, ~20h
// silence, recovery 2026-11-09T12:46Z, live-verified against the
// warehouse) is the acceptance fixture.

import { describe, it, expect } from "vitest";
import {
  resolveEntity,
  detectGaps,
  deterministicVerdict,
  gapPipelineShaped,
  type VolumeRow,
  type GlobalRow,
  type LogGap,
} from "./investigate";
import {
  classifyLine,
  hourlyVolumeSql,
  ENTITY_SYNTAX,
  classLabel,
  classColumn,
  CLASS_IDS,
  DISTRESS_CLASSES,
} from "../investigate/taxonomy";
import { compilePlan } from "../catalog/validate";
import { buildPreview } from "../investigate/preview";
import type { QueryPlan } from "../catalog/types";
import type { ServiceEnv } from "../bindings";

const HOUR = 3600_000;
const NOW = Date.parse("2026-11-09T14:00:00Z");

// Stub D1 that answers meta reads with a fixed observed-hosts payload.
function envWithObserved(hosts: string[]): ServiceEnv {
  const value = JSON.stringify(hosts.map((h) => ({ host: h, lastSeen: "" })));
  const stmt = {
    bind: () => stmt,
    first: async () => ({ value }),
    all: async () => ({ results: [] }),
    run: async () => ({}),
  };
  return {
    ACCOUNT_ID: "test",
    BUCKET: "test",
    REPORTS_D1: { prepare: () => stmt } as never,
  };
}

describe("resolveEntity", () => {
  it("resolves an observed host exactly", async () => {
    const r = await resolveEntity(envWithObserved(["HTPC", "seerr"]), "HTPC");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.entity.host).toBe("HTPC");
  });

  it("matches case-insensitively and by containment", async () => {
    const r = await resolveEntity(envWithObserved(["HTPC"]), "htpc");
    expect(r.ok).toBe(true);
    const r2 = await resolveEntity(envWithObserved(["HTPC"]), "the htpc server");
    expect(r2.ok && r2.entity.host).toBe("HTPC");
  });

  it("rejects unknown hosts with the known-host hint", async () => {
    const r = await resolveEntity(envWithObserved(["HTPC", "seerr"]), "nonexistent-box");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.kind).toBe("empty");
  });

  it("flags ambiguity when several hosts contain the token", async () => {
    const r = await resolveEntity(envWithObserved(["zz-host-alpha", "zz-host-beta"]), "zz-host");
    expect(r.ok).toBe(false);
    if (!r.ok && r.kind === "ambiguous") {
      expect(r.candidates.sort()).toEqual(["zz-host-alpha", "zz-host-beta"]);
    }
  });

  it("never lets a hostile entity string through: no SQL metacharacters accepted downstream", () => {
    expect(ENTITY_SYNTAX.test("HTPC")).toBe(true);
    expect(ENTITY_SYNTAX.test("'; DROP TABLE x")).toBe(false);
    expect(ENTITY_SYNTAX.test("%wildcard%")).toBe(false);
    expect(ENTITY_SYNTAX.test("")).toBe(false);
  });
});

describe("detectGaps (HTPC acceptance fixture)", () => {
  // 7 days hourly; the HTPC went silent at 2026-11-08T16:29Z and resumed
  // 2026-11-09T12:46Z. Reconstructed as ~20 missing hours.
  const from = NOW - 7 * 24 * HOUR;
  const gapStart = Date.parse("2026-11-08T17:00:00Z");
  const gapEnd = Date.parse("2026-11-09T12:00:00Z");
  const rows: VolumeRow[] = [];
  for (let t = from; t < NOW; t += HOUR) {
    if (t >= gapStart && t < gapEnd) continue; // the silence
    if (t >= NOW - HOUR) continue; // fresh commit-lag silence at the edge
    rows.push({ bucket: new Date(t).toISOString(), total: 50 + (t % 7) * 5 });
  }

  it("finds the 19-hour silence as a single gap", () => {
    const gaps = detectGaps(from, NOW, rows);
    expect(gaps.length).toBe(1);
    expect(gaps[0].startMs).toBe(gapStart);
    expect(gaps[0].endMs).toBe(gapEnd);
    expect(gaps[0].hours).toBeGreaterThanOrEqual(19);
    expect(gaps[0].hours).toBeLessThanOrEqual(21);
  });

  it("does not flag a chatty host's normal hour-to-hour jitter", () => {
    const gaps = detectGaps(from, NOW, rows.filter((r) => true));
    expect(gaps.every((g) => g.hours >= 2)).toBe(true);
  });

  it("ignores sporadic hosts' normal pauses (3x median rule)", () => {
    // Logs once every ~6 hours: 7 days of that, no incident.
    const sporadic: VolumeRow[] = [];
    for (let t = from; t < NOW - HOUR; t += 6 * HOUR) {
      sporadic.push({ bucket: new Date(t).toISOString(), total: 3 });
    }
    expect(detectGaps(from, NOW, sporadic)).toEqual([]);
  });

  it("treats trailing silence as an open gap", () => {
    // A host that died 5 hours ago: rows stop 5h before now.
    const dead: VolumeRow[] = [];
    for (let t = from; t < NOW - 5 * HOUR; t += HOUR) {
      dead.push({ bucket: new Date(t).toISOString(), total: 40 });
    }
    const gaps = detectGaps(from, NOW, dead);
    expect(gaps.length).toBe(1);
    expect(gaps[0].hours).toBeGreaterThanOrEqual(4);
    expect(gaps[0].endMs).toBeGreaterThan(NOW - 2 * HOUR);
  });
});

describe("classifyLine", () => {
  it("prioritises panic over everything", () => {
    expect(classifyLine("kernel: Kernel panic - not syncing")).toBe("panic-oops");
  });
  it("classifies oom kills", () => {
    expect(classifyLine("Out of memory: Killed process 123 (kodi)")).toBe("oom-kill");
  });
  it("SMART and I/O errors", () => {
    expect(classifyLine("smartd: SMART error (CurrentPendingSector) detected")).toBe("smart-error");
    expect(classifyLine("blk_update_request: I/O error")).toBe("io-error");
  });
  it("a service exit inside a shutdown cascade counts as shutdown, not service-failure", () => {
    expect(classifyLine("Reached target shutdown.target - Shutdown")).toBe("shutdown-cascade");
    expect(classifyLine("Stopping pipewire.service - PipeWire")).toBe("shutdown-cascade");
  });
  it("an isolated service failure is service-failure", () => {
    expect(classifyLine("foo.service: Main process exited, code=exited, status=1/FAILURE")).toBe(
      "service-failure",
    );
  });
  it("boot markers and auth lines", () => {
    expect(classifyLine("Startup finished in 5.123s (kernel)")).toBe("boot-cascade");
    expect(classifyLine("sshd: Failed password for root from 1.2.3.4")).toBe("auth-activity");
  });
  it("routine chatter stays routine", () => {
    expect(classifyLine("cron: (ian) CMD (echo hi)")).toBe("routine");
  });
  it("taxonomy sanity: every class has patterns and a distinct column name", () => {
    for (const cls of DISTRESS_CLASSES) {
      expect(cls.patterns.length).toBeGreaterThan(0);
      expect(classColumn(cls.id)).toMatch(/^[a-z_]+$/);
    }
    expect(new Set(CLASS_IDS.map(classColumn)).size).toBe(CLASS_IDS.length);
    expect(classLabel("oom-kill")).toBe("out of memory kill");
  });
});

describe("hourlyVolumeSql", () => {
  it("embeds the sqlLit host literal and every class column", () => {
    const sql = hourlyVolumeSql("HTPC", "2026-11-01T00:00:00Z", "2026-11-09T00:00:00Z", "hour", 200);
    expect(sql).toContain(`host = 'HTPC'`);
    expect(sql).toContain("AS total");
    for (const id of CLASS_IDS) expect(sql).toContain(`AS ${classColumn(id)}`);
    expect(sql).toContain("__ingest_ts >= '2026-11-01T00:00:00Z'");
  });
});

describe("compilePlan: log-timeline", () => {
  const plan = (over: Partial<QueryPlan>): QueryPlan => ({
    archetype: "log-timeline",
    table: "homelab.syslog",
    fromUTC: "2026-11-08T00:00:00Z",
    toUTC: "2026-11-09T00:00:00Z",
    entity: "HTPC",
    ...over,
  });

  it("compiles the hourly volume query for a valid entity", () => {
    const out = compilePlan(plan({}), "q", new Date("2026-11-09T14:00:00Z"));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.compiled.sql).toContain("host = 'HTPC'");
    expect(out.chart?.missingDataPolicy).toBe("gap");
    expect(out.notes.some((n) => n.includes("untrusted"))).toBe(true);
  });

  it("rejects a missing or hostile entity at compile time", () => {
    const noEntity = compilePlan(plan({ entity: "" }), "q", new Date());
    expect(noEntity.ok).toBe(false);
    const hostile = compilePlan(plan({ entity: "'; DROP TABLE reports" }), "q", new Date());
    expect(hostile.ok).toBe(false);
  });

  it("rejects other tables", () => {
    const wrong = compilePlan(
      plan({ table: "homelab.dns_queries" }),
      "q",
      new Date("2026-11-09T14:00:00Z"),
    );
    expect(wrong.ok).toBe(false);
  });

  it("investigate plans never compile: the loop owns execution", () => {
    const inv = compilePlan(
      plan({ archetype: "investigate" }),
      "q",
      new Date("2026-11-09T14:00:00Z"),
    );
    expect(inv.ok).toBe(false);
    if (inv.ok) return;
    expect("error" in inv && inv.error).toContain("investigation service");
  });
});

describe("gapPipelineShaped", () => {
  const gap: LogGap = {
    startMs: Date.parse("2026-11-08T17:00:00Z"),
    endMs: Date.parse("2026-11-09T12:00:00Z"),
    hours: 19,
  };

  it("flags a global ingestion hole: all other hours empty too", () => {
    const global: GlobalRow[] = [];
    expect(gapPipelineShaped(global, gap)).toBe(true);
  });

  it("does not flag a host-specific silence: other hosts kept logging", () => {
    const global: GlobalRow[] = [];
    for (let t = gap.startMs; t < gap.endMs; t += HOUR) {
      global.push({ bucket: new Date(t).toISOString(), total: 50 });
    }
    expect(gapPipelineShaped(global, gap)).toBe(false);
  });

  it("tolerates a couple of quiet hours in an otherwise healthy window", () => {
    const global: GlobalRow[] = [];
    let i = 0;
    for (let t = gap.startMs; t < gap.endMs; t += HOUR) {
      global.push({ bucket: new Date(t).toISOString(), total: i % 9 === 0 ? 0 : 50 });
      i++;
    }
    expect(gapPipelineShaped(global, gap)).toBe(false);
  });
});

describe("deterministicVerdict", () => {
  it("states the abrupt stop and the root-cause limit for the HTPC shape", () => {
    const v = deterministicVerdict({
      host: "HTPC",
      windowFromUTC: "2026-11-02T14:00:00Z",
      windowToUTC: "2026-11-09T14:00:00Z",
      windowHours: 168,
      hourly: [],
      totalsPerClass: { "oom-kill": 2, routine: 4000 },
      gaps: [
        {
          startUTC: "2026-11-08T17:00:00Z",
          endUTC: "2026-11-09T12:00:00Z",
          hours: 19,
          abruptStop: true,
          cleanRestart: true,
          pipelineShaped: false,
          linesBefore: 100,
          linesAfter: 50,
          classesBefore: { routine: 90, "shutdown-cascade": 0 },
          classesAfter: { "boot-cascade": 30, routine: 20 },
        },
      ],
      linesInWindow: 4000,
    });
    expect(v.verdict).toContain("abruptly");
    expect(v.verdict).toContain("not captured");
    expect(v.findings[0].classification).toBe("supported");
    expect(v.confidence).toBe("medium");
  });

  it("no gaps produces the honest widen-the-window verdict", () => {
    const v = deterministicVerdict({
      host: "HTPC",
      windowFromUTC: "2026-11-08T14:00:00Z",
      windowToUTC: "2026-11-09T14:00:00Z",
      windowHours: 24,
      hourly: [{ bucket: "2026-11-09T13:00:00Z", total: 10 }],
      totalsPerClass: {},
      gaps: [],
      linesInWindow: 10,
    });
    expect(v.verdict).toContain("no log silence");
    expect(v.nextSteps.join(" ")).toContain("widen");
  });

  it("identifies a pipeline-shaped hole instead of blaming the host", () => {
    const v = deterministicVerdict({
      host: "GL-AXT1800",
      windowFromUTC: "2026-11-03T14:00:00Z",
      windowToUTC: "2026-11-10T14:00:00Z",
      windowHours: 168,
      hourly: [],
      totalsPerClass: {},
      gaps: [
        {
          startUTC: "2026-11-08T17:00:00Z",
          endUTC: "2026-11-09T12:00:00Z",
          hours: 19,
          abruptStop: true,
          cleanRestart: true,
          pipelineShaped: true,
          linesBefore: 100,
          linesAfter: 50,
          classesBefore: {},
          classesAfter: {},
        },
      ],
      linesInWindow: 5000,
    });
    expect(v.verdict).toContain("global ingestion hole");
    expect(v.verdict).toContain("not evidence about this host");
    expect(v.verdict).not.toContain("Root cause (power loss");
    expect(v.findings[0].classification).toBe("supported");
  });
});

describe("previews: new detector + ask investigation", () => {
  it("host-silence preview names the host and age", () => {
    expect(
      buildPreview("host-silence", { host: "HTPC", quietMin: 52, avgHourly: 370 }),
    ).toBe("host HTPC silent 52m (baseline ~370 lines/h)");
  });

  it("ask-investigation preview states the gap and abruptness", () => {
    expect(
      buildPreview("ask-investigation", { host: "HTPC", gapHours: 19, abrupt: true }),
    ).toBe("HTPC: 19h log silence (abrupt stop) investigated");
    expect(
      buildPreview("ask-investigation", { host: "HTPC", gapHours: 3, abrupt: false }),
    ).toBe("HTPC: 3h log silence investigated");
    expect(
      buildPreview("ask-investigation", { host: "HTPC", gapHours: 19, abrupt: true, pipeline: true }),
    ).toBe("HTPC: 19h log silence (global ingestion hole) investigated");
  });
});
