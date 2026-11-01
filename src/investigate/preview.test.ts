// Investigation detector tests: preview strings, WAN verdicts and the
// congestion firing rule. All pure logic; the SQL scans are live-verified
// against the warehouse (see the detectors.ts comments for the verified
// dates) and exercised end-to-end by the */5 scheduler.

import { describe, it, expect } from "vitest";
import { buildPreview, radioLabel } from "./preview";
import { wanVerdicts, congestionFires, patternKey } from "./detectors";

const MIN = 60_000;
const NOW = Date.parse("2026-11-01T07:00:00Z");

describe("buildPreview", () => {
  it("names the entity and metric for every detector shape", () => {
    expect(
      buildPreview("dns-volume", { clientHash: "abcd1234efgh", candidateCount: 1200, windowMinutes: 10.00675 }),
    ).toBe("abcd1234efgh: 1200 DNS queries in 10m");
    expect(
      buildPreview("ssh-brute-force", { host: "server111", authFail: 24, topSources: [{ ip: "192.168.86.249", count: 20 }] }),
    ).toBe("server111: 24 failed auths from 192.168.86.249");
    expect(
      buildPreview("host-distress", { host: "server111", oom: 2, distress: 5, sampleUnit: "grafana.service" }),
    ).toBe("server111: 2 OOM, 5 distress lines (grafana.service)");
    expect(
      buildPreview("telemetry-blind-spot", { source: "homelab.syslog", detail: "newest row is 44 minutes old" }),
    ).toBe("homelab.syslog: newest row is 44 minutes old");
    expect(
      buildPreview("worker-errors", { bad: 40, scripts: { "basin-flowviz": 40 } }),
    ).toBe("40 non-ok Worker outcomes (basin-flowviz)");
  });

  it("wifi previews carry the radio band and the metric", () => {
    expect(
      buildPreview("wifi-degradation", {
        scope: "ap", ap: "Kids-U6-Pro", radio: "na", channel: 149, avgCuTotal: 78.2,
      }),
    ).toBe("AP Kids-U6-Pro 5 GHz ch149: 78.2% airtime");
    expect(
      buildPreview("wifi-degradation", {
        scope: "client", client: "HeleniPhone15", avgSignal: -84.3, ap: "Upstairs-U6-IW",
      }),
    ).toBe("client HeleniPhone15: -84.3 dBm avg on Upstairs-U6-IW");
    expect(
      buildPreview("wifi-congestion", {
        ap: "LivingRoom-U6-Pro", radio: "ng", channel: 6,
        avgCuTotal: 82, avgNumSta: 22, avgSatisfaction: 55,
      }),
    ).toBe("AP LivingRoom-U6-Pro 2.4 GHz ch6: 82% airtime, 22 clients, satisfaction 55%");
  });

  it("wan previews state the failure mode and age", () => {
    expect(
      buildPreview("wan-outage", { scope: "heartbeat", wanStaleMin: 52, routerQuietMin: 3 }),
    ).toBe("WAN lease renewals stopped 52m ago while the router keeps logging");
    expect(
      buildPreview("wan-outage", { scope: "router-silent", routerQuietMin: 61 }),
    ).toBe("router silent 61m; WAN state unknown");
    expect(
      buildPreview("wan-outage", { scope: "ip-change", previousIp: "144.6.128.151", wanIp: "144.6.131.7" }),
    ).toBe("WAN IP changed: 144.6.128.151 -> 144.6.131.7");
  });

  it("caps output and degrades gracefully on missing fields", () => {
    const long = buildPreview("telemetry-blind-spot", {
      source: "x",
      detail: "y".repeat(400),
    });
    expect(long.length).toBeLessThanOrEqual(100);
    expect(buildPreview("unknown-detector", {})).toBe("unknown-detector");
    expect(buildPreview("wifi-degradation", { scope: "client", client: "HeleniPhone15" })).not.toContain("NaN");
  });

  it("labels UniFi radio names readably", () => {
    expect(radioLabel("na")).toBe("5 GHz");
    expect(radioLabel("ng")).toBe("2.4 GHz");
    expect(radioLabel("")).toBe("radio");
  });
});

describe("wanVerdicts", () => {
  it("healthy heartbeat produces no connectivity verdict", () => {
    expect(wanVerdicts(NOW, NOW - 15 * MIN, NOW - 3 * MIN, "144.6.128.151", "144.6.128.151")).toEqual([]);
  });

  it("renewals stopped while the router still logs: heartbeat, high severity", () => {
    const v = wanVerdicts(NOW, NOW - 52 * MIN, NOW - 4 * MIN, "144.6.128.151", "144.6.128.151");
    expect(v).toHaveLength(1);
    expect(v[0].scope).toBe("heartbeat");
    expect(v[0].severity).toBe("high");
    expect(v[0].context.wanStaleMin).toBe(52);
  });

  it("router fully quiet: router-silent, low severity, honest unknown", () => {
    const v = wanVerdicts(NOW, NOW - 70 * MIN, NOW - 61 * MIN, "", "");
    expect(v).toHaveLength(1);
    expect(v[0].scope).toBe("router-silent");
    expect(v[0].severity).toBe("low");
  });

  it("no WAN rows at all in the lookback is a heartbeat stop if the router logs", () => {
    const v = wanVerdicts(NOW, null, NOW - 2 * MIN, "", "");
    expect(v[0].scope).toBe("heartbeat");
  });

  it("WAN IP change is reported independently and is low severity", () => {
    const v = wanVerdicts(NOW, NOW - 10 * MIN, NOW - 2 * MIN, "144.6.131.7", "144.6.128.151");
    expect(v).toHaveLength(1);
    expect(v[0].scope).toBe("ip-change");
    expect(v[0].severity).toBe("low");
    expect(v[0].context.previousIp).toBe("144.6.128.151");
    // First sighting (no previous IP recorded): just learn it, no report.
    expect(wanVerdicts(NOW, NOW - 10 * MIN, NOW - 2 * MIN, "144.6.128.151", null)).toEqual([]);
  });

  it("a stale renewal plus an IP change yields both verdicts", () => {
    const v = wanVerdicts(NOW, NOW - 55 * MIN, NOW - 5 * MIN, "144.6.131.7", "144.6.128.151");
    expect(v.map((x) => x.scope)).toEqual(["heartbeat", "ip-change"]);
  });
});

describe("congestionFires", () => {
  it("requires airtime saturation first", () => {
    expect(congestionFires(27.7, 55, 30, 40, 20)).toBe(false);
    expect(congestionFires(70.1, 99, 1, 0, 20)).toBe(false);
  });

  it("needs enough samples", () => {
    expect(congestionFires(80, 50, 30, 40, 5)).toBe(false);
  });

  it("high airtime alone is not congestion without a corroborator", () => {
    expect(congestionFires(82, 97, 12, 18, 15)).toBe(false);
  });

  it("fires on saturation plus satisfaction, station count or retries", () => {
    expect(congestionFires(82, 55, 12, 18, 15)).toBe(true);
    expect(congestionFires(82, 97, 26, 18, 15)).toBe(true);
    expect(congestionFires(82, 97, 12, 35, 15)).toBe(true);
  });

  it("normal retries at this site never corroborate alone", () => {
    // Live-observed shape: 19.6% retries on a 27.7% cu day must not fire.
    expect(congestionFires(27.7, 96, 13, 19.6, 58)).toBe(false);
  });
});

describe("patternKey (regression: keys with slashes)", () => {
  it("extracts the entity from per-radio wifi keys", () => {
    expect(patternKey("wifi-congestion:Kids-U6-Pro/na:2026-11-01", "wifi-congestion")).toBe(
      "wifi-congestion:Kids-U6-Pro/na",
    );
    expect(patternKey("wifi-degradation:LivingRoom-U6-Pro/ng:2026-11-01", "wifi-degradation")).toBe(
      "wifi-degradation:LivingRoom-U6-Pro/ng",
    );
  });
});
