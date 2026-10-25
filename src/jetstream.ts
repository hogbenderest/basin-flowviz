// JetstreamConsumer: the resident Durable Object that holds the Bluesky
// Jetstream WebSocket, batches events under the 5 MB ingest limit, persists
// the cursor, and enforces the UI toggle. Based on the Cloudflare docs example
// https://developers.cloudflare.com/basin-pipelines/examples/bluesky-firehose-fanout/
// extended with: persisted enabled flag, explicit socket close on deactivate,
// counters for the stats header, a per-flush sampled push to TickerHub,
// bounded catch-up, and the audit run 1 fixes (2026-10-24): single-flight
// connect, post-await enabled re-check, self-healing alarm, FLUSH_MAX-sized
// batches, bounded retry buffer, and validated cursors.
//
// Security note: this Worker runs with `logpush = true`, so console output
// lands in the workers_trace_events table the demo visualizes. Never log
// secrets, tokens, or raw request bodies.

import { DurableObject } from "cloudflare:workers";

export interface TickerEvent {
  source: string;
  kind: string;
  text: string;
  ts: string;
}

const COLLECTION_TO_TYPE: Record<string, string> = {
  "app.bsky.feed.post": "post",
  "app.bsky.feed.like": "like",
  "app.bsky.feed.repost": "repost",
  "app.bsky.graph.follow": "follow",
  "app.bsky.graph.block": "block",
};
const WANTED = Object.keys(COLLECTION_TO_TYPE);
const JETSTREAM_URL = "https://jetstream2.us-east.bsky.network/subscribe";
const FLUSH_MAX = 500; // rows per send(); each batch stays far under 5 MB
const FLUSH_MS = 1000; // flush at least once per second
const RECONNECT_MS = 15000;
const TICKER_SAMPLE = 2; // rows per ticker push
const TICKER_MIN_INTERVAL_MS = 2000; // at most one push per 2s (~1 row/s)
const BUF_MAX = 2000; // drop oldest rows beyond this (protects memory)
const CURSOR_STALE_US = 120_000_000; // cursor >120s old = skip the backlog
const CURSOR_GRACE_US = 60_000_000; // resume no further back than 60s
const CURSOR_FUTURE_SLACK_US = 600_000_000; // 10 min: future cursors are garbage
const SEND_FAIL_LOG_EVERY = 20; // one log line per 20 consecutive failures

// Field caps: the feed is untrusted global input, so no row field may be
// unbounded (protocol-bounded anyway, this is belt and braces).
const cap = (v: unknown, n: number): string | null =>
  typeof v === "string" ? v.slice(0, n) : null;

// Flatten one Jetstream message into the union stream row, or null to skip.
function toRow(ev: any): Record<string, unknown> | null {
  if (ev?.kind !== "commit" || !ev.commit) return null;
  const c = ev.commit;
  const event_type = COLLECTION_TO_TYPE[c.collection];
  if (!event_type) return null;
  const r = c.record ?? {};
  const subject = r.subject;
  return {
    event_id: cap(`${ev.did}/${c.collection}/${c.rkey}`, 200),
    event_type,
    did: cap(ev.did, 100),
    operation: cap(c.operation, 20),
    event_time:
      typeof ev.time_us === "number" ? new Date(ev.time_us / 1000).toISOString() : null,
    created_at: cap(r.createdAt, 40),
    text: event_type === "post" ? cap(r.text, 400) : null,
    langs: event_type === "post" && Array.isArray(r.langs) ? cap(r.langs.join(","), 100) : null,
    subject_uri: typeof subject === "object" ? cap(subject?.uri, 200) : null,
    subject_did: typeof subject === "string" ? cap(subject, 100) : null,
  };
}

// Humanized, short, single-line ticker text. Never emit raw at:// URIs or
// DIDs: they are unreadable, and their unbreakable length blows out the
// ticker layout (2026-10-22 ticker fix).
function tickerText(row: Record<string, unknown>): string {
  const kind = String(row.event_type ?? "event");
  if (typeof row.text === "string" && row.text.trim()) {
    return row.text.replace(/\s+/g, " ").trim().slice(0, 80);
  }
  switch (kind) {
    case "like":
      return "liked a post";
    case "repost":
      return "reposted a post";
    case "follow":
      return "followed a user";
    case "block":
      return "blocked a user";
    default:
      return kind;
  }
}

export class JetstreamConsumer extends DurableObject {
  private ws: WebSocket | null = null;
  private buf: Record<string, unknown>[] = [];
  private lastFlush = 0;
  private cursor: number | null = null;
  private flushing = false;
  private connecting: Promise<void> | null = null;
  private counters = { seen: 0, batches: 0, lastEventTs: 0 };
  private loaded = false;
  private lastTickerPush = 0;
  private sendFails = 0;

  private stream(): { send(records: Record<string, unknown>[]): Promise<void> } {
    return (this.env as any).BSKY_STREAM;
  }

  private hub(): any {
    const ns = (this.env as any).TICKER;
    return ns.get(ns.idFromName("hub"));
  }

  private async load(): Promise<void> {
    if (this.loaded) return;
    if (this.cursor === null)
      this.cursor = (await this.ctx.storage.get<number>("cursor")) ?? null;
    const c = await this.ctx.storage.get<{
      seen: number;
      batches: number;
      lastEventTs: number;
    }>("counters");
    if (c) this.counters = c;
    this.loaded = true;
  }

  // Public RPC: called by the Worker fetch route and by the cron keepalive.
  async start(): Promise<{ enabled: boolean; connected: boolean }> {
    await this.load();
    const enabled = (await this.ctx.storage.get<boolean>("enabled")) ?? false;
    if (!enabled) {
      await this.closeSocket();
      return { enabled: false, connected: false };
    }
    await this.ctx.storage.setAlarm(Date.now() + RECONNECT_MS);
    await this.ensureConnected();
    return { enabled: true, connected: this.ws !== null };
  }

  // Public RPC: the UI toggle. Off means close the socket and drop the
  // buffer; the persisted cursor is kept for gapless (bounded) resume.
  async setEnabled(enabled: boolean): Promise<{ enabled: boolean; connected: boolean }> {
    await this.ctx.storage.put("enabled", enabled);
    if (!enabled) {
      this.buf = [];
      await this.closeSocket();
      await this.ctx.storage.deleteAlarm();
      return { enabled: false, connected: false };
    }
    return this.start();
  }

  private async closeSocket(): Promise<void> {
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        /* already closed */
      }
      this.ws = null;
    }
  }

  private async ensureConnected(): Promise<void> {
    // Single-flight: concurrent callers (toggle races, alarm + cron) await the
    // same handshake instead of creating orphan sockets.
    if (this.ws) return;
    if (this.connecting) return this.connecting;
    this.connecting = this.doConnect();
    try {
      await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  private async doConnect(): Promise<void> {
    await this.load();
    // Bounded catch-up, both directions: a cursor more than ~2 minutes old
    // would trigger a full replay storm (measured ~10k events/s, crashed the
    // DO on 2026-10-22); a cursor far in the future is upstream garbage.
    // Either way, resume inside the grace window.
    const nowUs = Date.now() * 1000;
    if (this.cursor !== null) {
      if (
        nowUs - this.cursor > CURSOR_STALE_US ||
        this.cursor - nowUs > CURSOR_FUTURE_SLACK_US
      ) {
        this.cursor = nowUs - CURSOR_GRACE_US;
        await this.ctx.storage.put("cursor", this.cursor);
      }
    }
    const params = new URLSearchParams();
    for (const c of WANTED) params.append("wantedCollections", c);
    if (this.cursor) params.set("cursor", String(this.cursor));
    const resp = await fetch(`${JETSTREAM_URL}?${params}`, {
      headers: { Upgrade: "websocket" },
    });
    const ws = resp.webSocket;
    if (!ws) throw new Error(`Jetstream handshake failed: ${resp.status}`);
    ws.accept();
    // Post-await gate: if the toggle was switched off while the handshake was
    // in flight, this socket must not survive.
    const enabled = (await this.ctx.storage.get<boolean>("enabled")) ?? false;
    if (!enabled) {
      try {
        ws.close();
      } catch {
        /* ignore */
      }
      return;
    }
    this.ws = ws;
    ws.addEventListener("message", (e) => this.onMessage(e));
    ws.addEventListener("close", () => {
      if (this.ws === ws) this.ws = null;
    });
    ws.addEventListener("error", () => {
      if (this.ws === ws) this.ws = null;
    });
  }

  private onMessage(e: MessageEvent): void {
    let ev: any;
    try {
      ev = JSON.parse(e.data as string);
    } catch {
      return;
    }
    // Cursor validation: only finite, sane, not-far-future values are kept.
    if (
      typeof ev.time_us === "number" &&
      Number.isFinite(ev.time_us) &&
      ev.time_us > 0 &&
      ev.time_us < Date.now() * 1000 + CURSOR_FUTURE_SLACK_US
    ) {
      this.cursor = ev.time_us;
    }
    const row = toRow(ev);
    if (row) {
      if (this.buf.length >= BUF_MAX) this.buf.shift();
      this.buf.push(row);
      this.counters.seen++;
      this.counters.lastEventTs = Date.now();
    }
    if (
      this.buf.length >= FLUSH_MAX ||
      Date.now() - this.lastFlush >= FLUSH_MS
    ) {
      void this.flush();
    }
  }

  // Send at most FLUSH_MAX rows per batch. On failure the failed batch goes
  // back to the FRONT and the combined buffer is trimmed to BUF_MAX (the
  // newest arrivals are dropped, the failed batch survives), so a sustained
  // outage can never grow memory or size-lock batches past the 5 MB limit.
  private async flush(): Promise<void> {
    if (this.flushing) return;
    this.flushing = true;
    try {
      while (this.buf.length > 0) {
        this.lastFlush = Date.now();
        const batch = this.buf.splice(0, FLUSH_MAX);
        const batchCursor = this.cursor;
        try {
          await this.stream().send(batch);
          this.sendFails = 0;
          this.counters.batches++;
          await this.ctx.storage.put("cursor", batchCursor);
          if (this.counters.batches % 25 === 0) {
            await this.ctx.storage.put("counters", this.counters);
          }
          this.pushTicker(batch);
        } catch {
          this.buf = [...batch, ...this.buf].slice(0, BUF_MAX);
          this.sendFails++;
          if (this.sendFails === 1 || this.sendFails % SEND_FAIL_LOG_EVERY === 0) {
            console.error(
              `jetstream send failing (consecutive failures: ${this.sendFails}); buffer capped at ${this.buf.length} rows`,
            );
          }
          return;
        }
      }
      await this.ctx.storage.put("counters", this.counters);
    } finally {
      this.flushing = false;
    }
  }

  // Best-effort ticker feed: small human-paced sample of the flushed batch.
  private pushTicker(batch: Record<string, unknown>[]): void {
    const now = Date.now();
    if (now - this.lastTickerPush < TICKER_MIN_INTERVAL_MS) return;
    this.lastTickerPush = now;
    const sample: TickerEvent[] = batch.slice(0, TICKER_SAMPLE).map((r) => ({
      source: "bluesky",
      kind: String(r.event_type ?? "event"),
      text: tickerText(r),
      ts: typeof r.event_time === "string" ? r.event_time : new Date().toISOString(),
      ...(typeof r.event_id === "string" && r.event_id
        ? { event_id: r.event_id.slice(0, 240) }
        : {}),
    }));
    if (!sample.length) return;
    try {
      void this.hub()
        .push(sample, "bluesky")
        .catch(() => {});
    } catch {
      /* ticker is best-effort */
    }
  }

  // Watchdog: reconnect if dropped, flush stragglers, always reschedule
  // while enabled. When disabled it self-heals: close any socket that a race
  // left behind, drop the alarm, and stop (setEnabled re-arms on toggle-on).
  async alarm(): Promise<void> {
    const enabled = (await this.ctx.storage.get<boolean>("enabled")) ?? false;
    if (!enabled) {
      await this.closeSocket();
      await this.ctx.storage.deleteAlarm();
      return;
    }
    try {
      await this.ensureConnected();
      await this.flush();
    } catch (err) {
      console.error(
        "jetstream alarm error",
        err instanceof Error ? err.message : String(err),
      );
    } finally {
      await this.ctx.storage.setAlarm(Date.now() + RECONNECT_MS);
    }
  }

  // Public RPC for /api/stats.
  async getStats(): Promise<{
    enabled: boolean;
    connected: boolean;
    seen: number;
    batches: number;
    lastEventTs: number;
  }> {
    await this.load();
    const enabled = (await this.ctx.storage.get<boolean>("enabled")) ?? false;
    return {
      enabled,
      connected: this.ws !== null,
      seen: this.counters.seen,
      batches: this.counters.batches,
      lastEventTs: this.counters.lastEventTs,
    };
  }
}
