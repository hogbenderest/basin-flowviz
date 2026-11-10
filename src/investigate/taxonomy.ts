// Distress taxonomy (run 9): the single source of truth for log-line
// pattern classes, shared by the log-timeline archetype compiler
// (validate.ts), the investigate loop (ask/investigate.ts) and the
// detectors. Code constants, not catalogue entries: the classifier must
// stay deterministic and versioned. The catalogue facts list the class
// NAMES so the planner knows they exist; meta docs mirror them.
//
// Classification contract: a line's class is the FIRST matching class
// in DISTRESS_CLASSES order (priority). SQL hourly counts count each
// class independently, so counts may overlap where one line matches two
// classes - they are diagnostic signals, not a partition.

import { sqlLit } from "../sql";

export type LineClassId =
  | "panic-oops"
  | "oom-kill"
  | "smart-error"
  | "io-error"
  | "shutdown-cascade"
  | "boot-cascade"
  | "service-failure"
  | "auth-activity"
  | "routine";

export interface DistressClass {
  id: LineClassId;
  label: string;
  // ILIKE fragments matched against homelab.syslog.message
  // (case-insensitive).
  patterns: string[];
}

// Priority order: earlier wins for single-line classification.
// panic > oom > smart > io > shutdown > boot > service-failure > auth:
// a "Main process exited" inside a shutdown cascade is a shutdown line.
export const DISTRESS_CLASSES: DistressClass[] = [
  {
    id: "panic-oops",
    label: "kernel panic / oops",
    patterns: [
      "%Kernel panic%",
      "%BUG: unable to handle%",
      "%general protection fault%",
      "%Oops:%",
      "%soft lockup%",
      "%hard lockup%",
      "%watchdog: BUG%",
    ],
  },
  {
    id: "oom-kill",
    label: "out of memory kill",
    patterns: ["%out of memory%", "%oom-killer%", "%Killed process%", "%Memory cgroup out of memory%"],
  },
  {
    id: "smart-error",
    label: "disk SMART error",
    patterns: [
      "%SMART error%",
      "%Reallocated_Sector%",
      "%Current_Pending_Sector%",
      "%Offline_Uncorrectable%",
      "%SMART Usage Attribute: 5 %",
      "%SMART Usage Attribute: 197%",
      "%SMART Usage Attribute: 198%",
    ],
  },
  {
    id: "io-error",
    label: "disk / filesystem I/O error",
    patterns: [
      "%I/O error%",
      "%Medium Error%",
      "%failed command%",
      "%Currently unreadable%",
      "%blk_update_request%",
      "%EXT4-fs error%",
      "%BTRFS error%",
      "%EXT4-fs warning%",
    ],
  },
  {
    id: "shutdown-cascade",
    label: "clean shutdown cascade",
    patterns: [
      "%Reached target shutdown%",
      "%Reached target reboot%",
      "%Reached target poweroff%",
      "%Powering off%",
      "%The system is going down%",
      "%Reached target exit.target%",
      "%Stopping%",
    ],
  },
  {
    id: "boot-cascade",
    label: "boot cascade",
    patterns: [
      "%Startup finished%",
      "%Welcome to%",
      "%Reached target basic.target%",
      "%Reached target graphical%",
      "%Reached target multi-user%",
      "%Mounted%",
      "%Started%",
    ],
  },
  {
    id: "service-failure",
    label: "service failure / restart",
    patterns: [
      "%main process exited%",
      "%Failed to start%",
      "%scheduled restart%",
      "%Failed with result%",
      "%status=1/FAILURE%",
      "%status=2/INVALIDARGUMENT%",
    ],
  },
  {
    id: "auth-activity",
    label: "SSH auth activity",
    patterns: ["%failed password%", "%invalid user%", "%accepted password%", "%accepted publickey%"],
  },
];

export const CLASS_IDS = DISTRESS_CLASSES.map((c) => c.id);

// Pure single-line classifier: first matching class wins, else routine.
// Never sees anything but the one line; safe for tests.
export function classifyLine(msg: string): LineClassId {
  const m = (msg ?? "").toLowerCase();
  for (const cls of DISTRESS_CLASSES) {
    for (const p of cls.patterns) {
      const needle = p.replace(/^%|%$/g, "").toLowerCase();
      if (m.includes(needle)) return cls.id;
    }
  }
  return "routine";
}

// Class label for chips / notes.
export function classLabel(id: LineClassId): string {
  return DISTRESS_CLASSES.find((c) => c.id === id)?.label ?? id;
}

// SQL column alias for a class id (panic-oops -> panic_oops).
export function classColumn(id: LineClassId): string {
  return id.replace(/-/g, "_");
}

// Per-class SUM(CASE WHEN ...) columns for hourly volume queries.
export function distressCaseSql(): string {
  return DISTRESS_CLASSES.map((cls) => {
    const matches = cls.patterns
      .map((p) => `message ILIKE ${sqlLit(p)}`)
      .join(" OR ");
    return `SUM(CASE WHEN ${matches} THEN 1 ELSE 0 END) AS ${classColumn(cls.id)}`;
  }).join(", ");
}

// Hourly (or daily) volume + per-class distress counts for one host.
// The shared building block of the log-timeline archetype and the
// investigate loop (run-9 challenger P2: one SQL generator, no drift).
// Time-bounded by __ingest_ts per the catalogue caveat (router-origin
// event times drift); bucketed by ts (event time).
export function hourlyVolumeSql(
  host: string,
  from: string,
  to: string,
  grain: "hour" | "day" = "hour",
  limit = 200,
): string {
  const h = sqlLit(host);
  return (
    `SELECT date_trunc('${grain}', ts) AS bucket, COUNT(*) AS total, ${distressCaseSql()} ` +
    `FROM homelab.syslog WHERE host = ${h} ` +
    `AND __ingest_ts >= ${sqlLit(from)} AND __ingest_ts < ${sqlLit(to)} ` +
    `GROUP BY date_trunc('${grain}', ts) ORDER BY bucket LIMIT ${limit}`
  );
}

// Entity syntax defense for anything that reaches a host literal: the
// model's raw string is resolved against the known host sets first; this
// is the compile-time backstop (validate.ts).
export const ENTITY_SYNTAX = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
