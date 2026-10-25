// TickerHub: hibernatable WebSocket hub for the browser ticker, plus a
// short recent-events ring buffer backing the SSE fallback endpoint.
// Fed by JetstreamConsumer (Bluesky) and the Worker /relay route (LAN).
//
// Audit run 1 fixes (2026-10-24): ring entries are pruned by TTL (1 hour)
// on read and on write, so a poisoned or stale entry cannot persist
// indefinitely or replay to new browsers after the firehose is off.

import { DurableObject } from "cloudflare:workers";

export interface TickerEvent {
  source: string;
  kind: string;
  text: string;
  ts: string;
  // W4 drill-through: the archive row id. LAN events get it once the
  // Vector relay projects event_id; Bluesky rows always have one.
  event_id?: string;
}

const RING_MAX = 100;
const RING_TTL_MS = 3600_000; // one hour; older entries are dropped on read

export class TickerHub extends DurableObject {
  private counters: { bsky: number; lan: number; lastTs: number } | null = null;
  private ring: TickerEvent[] | null = null;

  private async load(): Promise<void> {
    if (this.counters === null) {
      const c = await this.ctx.storage.get<{
        bsky: number;
        lan: number;
        lastTs: number;
      }>("counters");
      this.counters = c ?? { bsky: 0, lan: 0, lastTs: 0 };
    }
    if (this.ring === null) {
      const r = await this.ctx.storage.get<TickerEvent[]>("ring");
      this.ring = Array.isArray(r) ? r : [];
    }
  }

  private fresh(): TickerEvent[] {
    const cutoff = Date.now() - RING_TTL_MS;
    return (this.ring ?? []).filter(
      (e) => (Date.parse(e.ts) || 0) > cutoff,
    );
  }

  // WebSocket upgrade for browsers: /ws -> hub.fetch(request).
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/ws" && req.headers.get("Upgrade") === "websocket") {
      await this.load();
      this.ring = this.fresh();
      const pair = new WebSocketPair();
      this.ctx.acceptWebSocket(pair[1], ["ticker"]);
      try {
        pair[1].send(
          JSON.stringify({
            type: "hello",
            recent: this.ring.slice(-25),
            counters: this.counters,
          }),
        );
      } catch {
        /* client gone */
      }
      return new Response(null, { status: 101, webSocket: pair[0] });
    }
    return new Response("not found", { status: 404 });
  }

  // Public RPC: JetstreamConsumer and /relay push batches here. Callers are
  // trusted (Worker code), but each event is still truncated defensively.
  async push(events: TickerEvent[], source: string): Promise<{ ok: boolean }> {
    await this.load();
    const clean: TickerEvent[] = [];
    for (const e of Array.isArray(events) ? events.slice(0, 30) : []) {
      if (!e || typeof e !== "object") continue;
      const id =
        typeof e.event_id === "string" && e.event_id ? e.event_id.slice(0, 240) : "";
      clean.push({
        source: String(e.source ?? source).slice(0, 10),
        kind: String(e.kind ?? "event").slice(0, 40),
        text: String(e.text ?? "").slice(0, 120),
        ts: String(e.ts ?? new Date().toISOString()).slice(0, 40),
        ...(id ? { event_id: id } : {}),
      });
    }
    if (clean.length) {
      this.ring!.push(...clean);
      this.ring = this.fresh();
      if (this.ring!.length > RING_MAX)
        this.ring = this.ring!.slice(-RING_MAX);
      const ts = Date.parse(clean[clean.length - 1].ts);
      this.counters!.lastTs = Number.isFinite(ts) ? ts : Date.now();
    }
    if (source === "bluesky") this.counters!.bsky += clean.length;
    else this.counters!.lan += clean.length;
    if (clean.length) {
      const sockets = this.ctx.getWebSockets("ticker");
      const msg = JSON.stringify({ type: "ticker", events: clean });
      for (const ws of sockets) {
        try {
          ws.send(msg);
        } catch {
          /* stale socket; hibernation API cleans it up */
        }
      }
    }
    await this.ctx.storage.put("counters", this.counters!);
    await this.ctx.storage.put("ring", this.ring!);
    return { ok: true };
  }

  // Public RPC for /api/stats.
  async getStats(): Promise<{
    bsky: number;
    lan: number;
    lastTs: number;
    clients: number;
  }> {
    await this.load();
    return {
      ...this.counters!,
      clients: this.ctx.getWebSockets("ticker").length,
    };
  }

  // Public RPC for the SSE fallback. TTL-pruned.
  async recent(): Promise<TickerEvent[]> {
    await this.load();
    this.ring = this.fresh();
    return this.ring.slice(-25);
  }
}
