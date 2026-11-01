// resolveWindow + compilePlan window-resolution tests.
//
// The live bug (2026-11-01): the planner model sometimes emits
// natural-language timestamps ("now", "last 24 hours") in fromUTC/toUTC.
// The old resolveWindow treated any truthy unparseable string as fatal
// ("invalid or missing time window"); the fix treats them as missing and
// falls back (session window, then the 24h default) while keeping the
// structural guardrails fatal.

import { describe, it, expect } from "vitest";
import { resolveWindow, compilePlan } from "./validate";
import type { QueryPlan } from "./types";

const NOW = new Date("2026-11-01T06:00:00.000Z");
const iso = (ms: number) => new Date(ms).toISOString();
const H = 3600_000;

function plan(partial: Partial<QueryPlan>): QueryPlan {
  return {
    archetype: "timeseries-count",
    table: "homelab.dns_queries",
    fromUTC: "",
    toUTC: "",
    ...partial,
  };
}

describe("resolveWindow", () => {
  it("defaults missing/empty values to now and the last 24 hours", () => {
    const w = resolveWindow(plan({}), NOW);
    expect(w).not.toBeNull();
    expect(w!.toUTC).toBe(NOW.toISOString());
    expect(Date.parse(w!.fromUTC)).toBe(NOW.getTime() - 24 * H);
    expect(w!.defaulted).toBe(true);
  });

  it("treats natural-language timestamps as missing, not fatal", () => {
    for (const bad of ["now", "today", "last 24 hours", "24 hours ago", "yesterday"]) {
      const w = resolveWindow(plan({ fromUTC: bad, toUTC: bad }), NOW);
      expect(w, `value "${bad}" must not fail the plan`).not.toBeNull();
      expect(w!.toUTC).toBe(NOW.toISOString());
      expect(w!.defaulted).toBe(true);
    }
  });

  it("accepts valid ISO timestamps without defaulting", () => {
    const w = resolveWindow(
      plan({ fromUTC: iso(NOW.getTime() - 2 * H), toUTC: iso(NOW.getTime()) }),
      NOW,
    );
    expect(w!.defaulted).toBe(false);
    expect(Date.parse(w!.toUTC)).toBe(NOW.getTime());
  });

  it("uses the session fallback when plan values are unparseable", () => {
    const w = resolveWindow(
      plan({ fromUTC: "garbage", toUTC: "now" }),
      NOW,
      { fromUTC: iso(NOW.getTime() - 48 * H), toUTC: iso(NOW.getTime() - 24 * H) },
    );
    expect(w!.defaulted).toBe(true);
    expect(Date.parse(w!.fromUTC)).toBe(NOW.getTime() - 48 * H);
    expect(Date.parse(w!.toUTC)).toBe(NOW.getTime() - 24 * H);
  });

  it("prefers plan values over the session fallback", () => {
    const w = resolveWindow(
      plan({ fromUTC: iso(NOW.getTime() - 2 * H), toUTC: iso(NOW.getTime()) }),
      NOW,
      { fromUTC: iso(NOW.getTime() - 48 * H), toUTC: iso(NOW.getTime() - 24 * H) },
    );
    expect(w!.defaulted).toBe(false);
    expect(Date.parse(w!.fromUTC)).toBe(NOW.getTime() - 2 * H);
  });

  it("recovers degenerate and future windows to the honest 24h default", () => {
    // Zero-width: the live "internet dropping out now" failure shape.
    // Both bounds are suspect, so the window resets to last-24h-to-now.
    const zw = resolveWindow(
      plan({ fromUTC: iso(NOW.getTime()), toUTC: iso(NOW.getTime()) }),
      NOW,
    );
    expect(zw, "zero-width window must recover, not fail").not.toBeNull();
    expect(zw!.defaulted).toBe(true);
    expect(Date.parse(zw!.toUTC)).toBe(NOW.getTime());
    expect(Date.parse(zw!.fromUTC)).toBe(NOW.getTime() - 24 * H);

    // Inverted range (live-observed: from=tomorrow, to=yesterday).
    const inv = resolveWindow(
      plan({ fromUTC: iso(NOW.getTime() + 24 * H), toUTC: iso(NOW.getTime() - 24 * H) }),
      NOW,
    );
    expect(inv, "inverted window must recover, not fail").not.toBeNull();
    expect(inv!.defaulted).toBe(true);
    expect(Date.parse(inv!.toUTC)).toBe(NOW.getTime());
    expect(Date.parse(inv!.fromUTC)).toBe(NOW.getTime() - 24 * H);

    // Future toUTC with a valid from (timezone slip): clamp to now,
    // keep the valid from bound.
    const fut = resolveWindow(
      plan({ fromUTC: iso(NOW.getTime() - 8 * H), toUTC: iso(NOW.getTime() + 8 * H) }),
      NOW,
    );
    expect(fut, "future-bounded window must clamp, not fail").not.toBeNull();
    expect(fut!.defaulted).toBe(true);
    expect(Date.parse(fut!.toUTC)).toBe(NOW.getTime());
    expect(Date.parse(fut!.fromUTC)).toBe(NOW.getTime() - 8 * H);

    // Future toUTC with from=now: clamping would leave a zero-width
    // sliver (live-observed: from=now, to=now+4h). Widen to 24h.
    const sliver = resolveWindow(
      plan({ fromUTC: iso(NOW.getTime() - 2000), toUTC: iso(NOW.getTime() + 4 * H) }),
      NOW,
    );
    expect(sliver).not.toBeNull();
    expect(sliver!.defaulted).toBe(true);
    expect(Date.parse(sliver!.toUTC)).toBe(NOW.getTime());
    expect(Date.parse(sliver!.fromUTC)).toBe(NOW.getTime() - 24 * H);

    // Whole window in the future: degenerate after the clamp, recovers.
    const allFut = resolveWindow(
      plan({ fromUTC: iso(NOW.getTime() + 2 * H), toUTC: iso(NOW.getTime() + 4 * H) }),
      NOW,
    );
    expect(allFut).not.toBeNull();
    expect(allFut!.defaulted).toBe(true);
    expect(Date.parse(allFut!.toUTC)).toBe(NOW.getTime());
  });

  it("keeps a deliberately narrow coherent window (recovery does not touch it)", () => {
    // A coherent 60 s window the model emitted on purpose is valid intent:
    // it stays, and will honestly return sparse data under commit lag.
    const w = resolveWindow(
      plan({ fromUTC: iso(NOW.getTime() - 60_000), toUTC: iso(NOW.getTime()) }),
      NOW,
    );
    expect(w!.defaulted).toBe(false);
    expect(Date.parse(w!.toUTC) - Date.parse(w!.fromUTC)).toBe(60_000);
  });

  it("still rejects a window that exceeds the 30-day cap", () => {
    // 13 months apart: valid ISO, deliberate intent, beyond the cap.
    expect(
      resolveWindow(
        plan({ fromUTC: "2025-10-01T00:00:00.000Z", toUTC: "2026-11-01T00:00:00.000Z" }),
        NOW,
      ),
    ).toBeNull();
  });
});

describe("compilePlan window handling", () => {
  it("recovers a garbage-window model plan with the 24h default and a note", () => {
    const out = compilePlan(plan({ fromUTC: "last 24 hours", toUTC: "now" }), "q", NOW);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.notes.some((n) => n.includes("Time window defaulted"))).toBe(true);
    expect(Date.parse(out.toUTC)).toBe(NOW.getTime());
    expect(Date.parse(out.fromUTC)).toBe(NOW.getTime() - 24 * H);
  });

  it("uses the session window for a garbage-window plan when provided", () => {
    const out = compilePlan(
      plan({ fromUTC: "junk", toUTC: "junk" }),
      "q",
      NOW,
      { fromUTC: iso(NOW.getTime() - 48 * H), toUTC: iso(NOW.getTime() - 24 * H) },
    );
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.notes.some((n) => n.includes("session scope"))).toBe(true);
    expect(Date.parse(out.fromUTC)).toBe(NOW.getTime() - 48 * H);
    expect(Date.parse(out.toUTC)).toBe(NOW.getTime() - 24 * H);
  });

  it("honours a verified question's windowHours when plan strings are empty (q-dns-hourly: 168h)", () => {
    const out = compilePlan(
      plan({ verifiedQueryId: "q-dns-hourly" }),
      "verified",
      NOW,
    );
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const spanH = (Date.parse(out.toUTC) - Date.parse(out.fromUTC)) / H;
    expect(spanH).toBeCloseTo(168, 0);
    // The 24h-default note must NOT appear: windowHours supplied the window.
    expect(out.notes.some((n) => n.includes("Time window defaulted"))).toBe(false);
  });

  it("still fails a model plan whose valid ISO window exceeds 30 days", () => {
    const out = compilePlan(
      plan({ fromUTC: "2025-10-01T00:00:00.000Z", toUTC: "2026-11-01T00:00:00.000Z" }),
      "q",
      NOW,
    );
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect("error" in out && out.error).toContain("time window");
  });
});
