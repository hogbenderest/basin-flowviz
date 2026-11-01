// Inbox list-row preview strings: one line of entity + metric context
// per report so the inbox itself supports triage (run-8 finding: the
// wifi-degradation notice showed neither the AP nor the client).
//
// Input is the detector candidate aggregate ONLY (never raw message
// bodies); output is capped hard. This module is pure so both the
// workflow (report assembly) and the scheduler (coalescence refresh)
// produce identical previews.

const MAX_LEN = 100;

function cap(s: string): string {
  return s.length > MAX_LEN ? s.slice(0, MAX_LEN - 1) + "\u2026" : s;
}

const N = (v: unknown, fallback = 0): number => {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
};
const S = (v: unknown): string => (v === undefined || v === null ? "" : String(v));

// UniFi radio names: na = 5 GHz (802.11a/n/ac/ax), ng = 2.4 GHz.
export function radioLabel(radio: string): string {
  if (radio === "na") return "5 GHz";
  if (radio === "ng") return "2.4 GHz";
  return radio || "radio";
}

type TopSource = { ip?: unknown; count?: unknown };

export function buildPreview(
  detectorId: string,
  c: Record<string, unknown>,
): string {
  switch (detectorId) {
    case "dns-volume": {
      const count = N(c.candidateCount);
      // windowMinutes arrives as a float (10.00675m observed): the
      // preview is a headline, not a measurement.
      const mins = Math.round(N(c.windowMinutes));
      const who = S(c.clientHash);
      return cap(`${who ? `${who.slice(0, 12)}: ` : ""}${count} DNS queries in ${mins}m`);
    }
    case "ssh-brute-force": {
      const top = (c.topSources as TopSource[] | undefined)?.[0];
      const src = top?.ip ? ` from ${S(top.ip)}` : "";
      return cap(`${S(c.host)}: ${N(c.authFail)} failed auths${src}`);
    }
    case "host-distress": {
      const unit = S(c.sampleUnit);
      return cap(
        `${S(c.host)}: ${N(c.oom)} OOM, ${N(c.distress)} distress lines${unit ? ` (${unit})` : ""}`,
      );
    }
    case "telemetry-blind-spot":
      return cap(`${S(c.source)}: ${S(c.detail)}`);
    case "worker-errors": {
      const scripts = c.scripts as Record<string, number> | undefined;
      const topScript = scripts
        ? Object.entries(scripts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? ""
        : "";
      return cap(`${N(c.bad)} non-ok Worker outcomes${topScript ? ` (${topScript})` : ""}`);
    }
    case "wifi-degradation": {
      if (S(c.scope) === "ap") {
        return cap(
          `AP ${S(c.ap)} ${radioLabel(S(c.radio))} ch${N(c.channel)}: ${N(c.avgCuTotal, 0)}% airtime`,
        );
      }
      const ap = S(c.ap);
      return cap(
        `client ${S(c.client)}: ${N(c.avgSignal)} dBm avg${ap ? ` on ${ap}` : ""}`,
      );
    }
    case "wifi-congestion":
      return cap(
        `AP ${S(c.ap)} ${radioLabel(S(c.radio))} ch${N(c.channel)}: ${N(c.avgCuTotal)}% airtime, ` +
          `${N(c.avgNumSta)} clients, satisfaction ${N(c.avgSatisfaction)}%`,
      );
    case "wan-outage": {
      const scope = S(c.scope);
      if (scope === "router-silent")
        return cap(`router silent ${N(c.routerQuietMin)}m; WAN state unknown`);
      if (scope === "ip-change")
        return cap(`WAN IP changed: ${S(c.previousIp) || "?"} -> ${S(c.wanIp) || "?"}`);
      return cap(
        `WAN lease renewals stopped ${N(c.wanStaleMin)}m ago while the router keeps logging`,
      );
    }
    default:
      return cap(detectorId);
  }
}
