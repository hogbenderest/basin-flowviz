/* Basin live data flow demo.
 *
 * Structure on purpose: the DATA section (columns + edges) is pure config,
 * the RENDER section draws it, and the LIVE section wires stats/ticker.
 * The renderer can be swapped (e.g. for React Flow later) without touching
 * data or live wiring.
 */
(() => {
  "use strict";

  // ------------------------------------------------------------------
  // DATA: five columns and the edge list. ids are referenced by EDGES.
  // ------------------------------------------------------------------

  const COLUMNS = [
    {
      id: "sources",
      title: "Sources",
      cards: [
        { id: "bsky", label: "Bluesky Jetstream", sub: "wss firehose, DO consumer", cls: "src" },
        { id: "ha", label: "Home Assistant", sub: "mqtt_statestream, HA Pi", cls: "src" },
        { id: "server111", label: "Homelab hosts", sub: "server111 + Pis: journald, metrics", cls: "src" },
        { id: "unifi", label: "UniFi", sub: "remote syslog + Integration API", cls: "src" },
        { id: "dns", label: "House DNS", sub: "dnsmasq via router syslog", cls: "src" },
        { id: "openwrt", label: "OpenWrt", sub: "remote syslog", cls: "src" },
        { id: "zone", label: "Zone logs", sub: "ihogben.com Logpush", cls: "src cf" },
        { id: "worker", label: "This Worker", sub: "workers_trace_events", cls: "src cf" },
      ],
    },
    {
      id: "streams",
      title: "Streams",
      cards: [
        { id: "s_bsky", label: "bsky_events_stream", sub: "Worker binding, HTTP off", cls: "stream" },
        { id: "s_ha", label: "ha_events", sub: "HTTP ingest, authed", cls: "stream" },
        { id: "s_hl", label: "homelab_events", sub: "HTTP ingest, authed", cls: "stream" },
        { id: "s_zhttp", label: "logpush: http_requests", sub: "auto-created", cls: "stream" },
        { id: "s_zfw", label: "logpush: firewall_events", sub: "auto-created", cls: "stream" },
        { id: "s_zdns", label: "logpush: dns_logs", sub: "auto-created", cls: "stream" },
        { id: "s_wt", label: "logpush: workers_trace_events", sub: "auto-created", cls: "stream" },
      ],
    },
    {
      id: "pipelines",
      title: "Pipelines",
      cards: [
        { id: "p_bsky", label: "bsky_pipeline", sub: "5x INSERT WHERE event_type", cls: "pipe" },
        { id: "p_ha", label: "ha_pipeline", sub: "2x INSERT", cls: "pipe" },
        { id: "p_hl", label: "homelab_pipeline", sub: "5x INSERT WHERE event_type", cls: "pipe" },
        { id: "p_lp", label: "Logpush pipelines", sub: "sha256 + noise drop, at job creation", cls: "pipe" },
      ],
    },
    {
      id: "tables",
      title: "Tables (Basin Catalog / Iceberg)",
      groups: [
        { name: "ns: bsky", cards: [
          { id: "t_post", label: "bsky_post", sub: "posts", cls: "table" },
          { id: "t_like", label: "bsky_like", sub: "likes", cls: "table" },
          { id: "t_repost", label: "bsky_repost", sub: "reposts", cls: "table" },
          { id: "t_follow", label: "bsky_follow", sub: "follows", cls: "table" },
          { id: "t_block", label: "bsky_block", sub: "blocks", cls: "table" },
        ]},
        { name: "ns: ha", cards: [
          { id: "t_ha_state", label: "ha_state_changes", sub: "state changes", cls: "table" },
          { id: "t_ha_sensor", label: "ha_sensor_readings", sub: "sensor readings", cls: "table" },
        ]},
        { name: "ns: homelab", cards: [
          { id: "t_syslog", label: "syslog", sub: "server111, Pis, OpenWrt, UniFi", cls: "table" },
          { id: "t_metrics", label: "host_metrics", sub: "per-host metrics", cls: "table" },
          { id: "t_udev", label: "unifi_devices", sub: "UniFi devices", cls: "table" },
          { id: "t_ucli", label: "unifi_clients", sub: "UniFi clients", cls: "table" },
          { id: "t_dnsq", label: "dns_queries", sub: "house DNS", cls: "table" },
        ]},
        { name: "ns: Logpush zone", cards: [
          { id: "t_zhttp", label: "ihogben: http_requests", sub: "hashed IPs", cls: "table" },
          { id: "t_zfw", label: "ihogben: firewall_events", sub: "WAF events", cls: "table" },
          { id: "t_zdns", label: "ihogben: dns_logs", sub: "zone DNS", cls: "table" },
        ]},
        { name: "ns: Worker", cards: [
          { id: "t_wt", label: "workers_trace_events", sub: "this Worker's own logs", cls: "table" },
        ]},
      ],
    },
    {
      id: "engines",
      title: "Query interop",
      groups: [
        { name: "included with Basin", cards: [
          { id: "e_sql", label: "Basin SQL", sub: "REST - live; used by this console", cls: "engine primary" },
        ]},
        { name: "direct interop (Iceberg REST)", note: "Open Iceberg tables: any compatible engine can read them via Basin Catalog. Not connected in this deployment.", cards: [
          { id: "e_duck", label: "DuckDB", sub: "reads via Basin Catalog", cls: "engine" },
          { id: "e_trino", label: "Trino", sub: "reads via Basin Catalog", cls: "engine" },
          { id: "e_snow", label: "Snowflake", sub: "via Basin Catalog; its compute billed separately", cls: "engine" },
          { id: "e_spark", label: "Apache Spark", sub: "PyIceberg interop", cls: "engine" },
          { id: "e_pyspark", label: "PySpark", sub: "writes to existing tables", cls: "engine" },
        ]},
        { name: "existing BI investments", note: "Keeps its existing connectors, pointed at the engines above. Not connected in this deployment.", cards: [
          { id: "e_tableau", label: "Tableau", sub: "keeps its connector; points it at Trino/Snowflake", cls: "engine" },
          { id: "e_qlik", label: "Qlik", sub: "via Trino / ODBC", cls: "engine" },
          { id: "e_powerbi", label: "Power BI", sub: "via Snowflake connector", cls: "engine" },
        ]},
      ],
    },
  ];

  // [from, to, color]
  const EDGES = [
    // Bluesky column (blue)
    ["bsky", "s_bsky", "blue"],
    ["s_bsky", "p_bsky", "blue"],
    ["p_bsky", "t_post", "blue"], ["p_bsky", "t_like", "blue"], ["p_bsky", "t_repost", "blue"],
    ["p_bsky", "t_follow", "blue"], ["p_bsky", "t_block", "blue"],
    // LAN columns (green)
    ["ha", "s_ha", "green"], ["server111", "s_hl", "green"], ["unifi", "s_hl", "green"],
    ["dns", "s_hl", "green"], ["openwrt", "s_hl", "green"],
    ["s_ha", "p_ha", "green"], ["s_hl", "p_hl", "green"],
    ["p_ha", "t_ha_state", "green"], ["p_ha", "t_ha_sensor", "green"],
    ["p_hl", "t_syslog", "green"], ["p_hl", "t_metrics", "green"], ["p_hl", "t_udev", "green"],
    ["p_hl", "t_ucli", "green"], ["p_hl", "t_dnsq", "green"],
    // Cloudflare columns (orange)
    ["zone", "s_zhttp", "orange"], ["zone", "s_zfw", "orange"], ["zone", "s_zdns", "orange"],
    ["worker", "s_wt", "orange"],
    ["s_zhttp", "p_lp", "orange"], ["s_zfw", "p_lp", "orange"], ["s_zdns", "p_lp", "orange"],
    ["s_wt", "p_lp", "orange"],
    ["p_lp", "t_zhttp", "orange"], ["p_lp", "t_zfw", "orange"], ["p_lp", "t_zdns", "orange"],
    ["p_lp", "t_wt", "orange"],
  ];

  // every table -> Basin SQL; a few interop edges
  const ALL_TABLES = [
    "t_post", "t_like", "t_repost", "t_follow", "t_block",
    "t_ha_state", "t_ha_sensor",
    "t_syslog", "t_metrics", "t_udev", "t_ucli", "t_dnsq",
    "t_zhttp", "t_zfw", "t_zdns", "t_wt",
  ];
  for (const t of ALL_TABLES) EDGES.push([t, "e_sql", "dim"]);
  EDGES.push(["t_post", "e_duck", "dim"], ["t_zhttp", "e_duck", "dim"]);
  EDGES.push(["t_dnsq", "e_trino", "dim"], ["t_syslog", "e_trino", "dim"]);
  EDGES.push(["t_zhttp", "e_snow", "dim"]);
  EDGES.push(["t_like", "e_spark", "dim"], ["t_post", "e_pyspark", "dim"]);
  // BI tools ride on the interop engines they already support.
  EDGES.push(["e_trino", "e_tableau", "dim"], ["e_trino", "e_qlik", "dim"], ["e_snow", "e_powerbi", "dim"]);

  // ------------------------------------------------------------------
  // RENDER
  // ------------------------------------------------------------------

  const flow = document.getElementById("flow");
  const svg = document.getElementById("edges");
  const columnsEl = document.getElementById("columns");

  function renderColumns() {
    columnsEl.innerHTML = "";
    for (const col of COLUMNS) {
      const colEl = document.createElement("section");
      colEl.className = "column";
      const t = document.createElement("div");
      t.className = "column-title";
      t.textContent = col.title;
      colEl.appendChild(t);
      const addCard = (c) => {
        const el = document.createElement("div");
        el.className = "card " + (c.cls || "");
        el.dataset.id = c.id;
        el.innerHTML = `<div class="card-title"></div><div class="card-sub"></div>`;
        el.querySelector(".card-title").textContent = c.label;
        el.querySelector(".card-sub").textContent = c.sub || "";
        el.addEventListener("click", () => {
          document.dispatchEvent(
            new CustomEvent("flowviz:card", { detail: { id: c.id, label: c.label } }),
          );
          // W8: table cards jump to the Ask tab with the scope set.
          if (ALL_TABLES.includes(c.id)) {
            setAskMode("ai");
            switchTab("ask");
          }
        });
        // W6: hovering a card brightens its edges; static interop edges
        // become visible invitations instead of fake ambient flow.
        el.addEventListener("mouseenter", () => {
          for (const e of edgePaths)
            if (e.to === c.id || e.from === c.id) e.pathEl.classList.add("edge-hover");
        });
        el.addEventListener("mouseleave", () => {
          for (const e of edgePaths)
            if (e.to === c.id || e.from === c.id) e.pathEl.classList.remove("edge-hover");
        });
        colEl.appendChild(el);
      };
      if (col.groups) {
        for (const g of col.groups) {
          const gh = document.createElement("div");
          gh.className = "group";
          gh.textContent = g.name;
          colEl.appendChild(gh);
          if (g.note) {
            const gn = document.createElement("div");
            gn.className = "group-note";
            gn.textContent = g.note;
            colEl.appendChild(gn);
          }
          for (const c of g.cards) addCard(c);
        }
      } else if (col.cards) {
        for (const c of col.cards) addCard(c);
      }
      columnsEl.appendChild(colEl);
    }
  }

  const edgePaths = []; // {pathEl, len, color, from, to}

  function layoutEdges() {
    const fr = flow.getBoundingClientRect();
    svg.setAttribute("viewBox", `0 0 ${fr.width} ${fr.height}`);
    svg.innerHTML = "";
    edgePaths.length = 0;
    particles.length = 0; // indexes are rebuilt below; drop in-flight particles
    circles.length = 0;
    for (const [from, to, color] of EDGES) {
      const a = columnsEl.querySelector(`[data-id="${from}"]`);
      const b = columnsEl.querySelector(`[data-id="${to}"]`);
      if (!a || !b) continue;
      const ra = a.getBoundingClientRect();
      const rb = b.getBoundingClientRect();
      // Skip edges whose either endpoint is scrolled out of the flow area:
      // a path anchored to a hidden card would sweep through the middle of
      // the screen, and its dots would appear to run off the bottom edge.
      // Edges materialize as their cards scroll into view.
      const M = 24;
      if (
        ra.top - fr.top > fr.height + M ||
        rb.top - fr.top > fr.height + M ||
        ra.bottom - fr.top < -M ||
        rb.bottom - fr.top < -M
      ) {
        continue;
      }
      const x1 = ra.right - fr.left;
      const y1 = ra.top + ra.height / 2 - fr.top;
      const x2 = rb.left - fr.left;
      const y2 = rb.top + rb.height / 2 - fr.top;
      const mx = (x1 + x2) / 2;
      const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
      p.setAttribute("d", `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`);
      p.setAttribute("stroke", color === "dim" ? "#212736" : "#2a3143");
      p.setAttribute("stroke-width", "1.4");
      p.setAttribute("fill", "none");
      p.setAttribute("data-from", from);
      p.setAttribute("data-to", to);
      svg.appendChild(p);
      edgePaths.push({ pathEl: p, len: p.getTotalLength(), color, from, to });
    }
  }

  // Re-layout on scroll/resize, debounced to one run per frame so paths
  // always track card positions (the Tables column scrolls; frozen paths
  // make dots miss their targets).
  let layoutQueued = false;
  function scheduleLayout() {
    if (layoutQueued) return;
    layoutQueued = true;
    requestAnimationFrame(() => {
      layoutQueued = false;
      layoutEdges();
    });
  }

  // ---- particles ----

  const particles = []; // {idx, t, speed, color}
  const COLORS = {
    blue: "#4aa3ff",
    green: "#2fd48f",
    orange: "#f6821f",
    dim: "#7a5a36",
    query: "#f6a54e",
  };
  const circles = [];

  function getCircle(i) {
    while (circles.length <= i) {
      const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      c.setAttribute("r", "3.1");
      c.setAttribute("opacity", "0.9");
      svg.appendChild(c);
      circles.push(c);
    }
    return circles[i];
  }

  // Ambient rates cover the real live sources only. The "dim" edges
  // (query path, interop, BI) get NO ambient particles (run-3 review W6):
  // they brighten on hover, and the Basin SQL edges pulse only when a
  // real query actually runs (pulseSqlEdges below).
  let rates = { blue: 0.4, green: 0.9, orange: 0.35 }; // particles/sec per color (ambient)
  const TARGET_CAP = { blue: 42, green: 60, orange: 26 };
  const liveCounts = { blue: 0, green: 0, orange: 0, dim: 0 };

  function countLive(color) {
    let n = 0;
    for (const p of particles) if (edgePaths[p.idx].color === color) n++;
    return n;
  }

  let lastFrame = performance.now();

  function frame(now) {
    const dt = Math.min((now - lastFrame) / 1000, 0.1);
    lastFrame = now;
    // W8: the map only animates while its tab is active.
    if (document.body.dataset.tab !== "flow") {
      requestAnimationFrame(frame);
      return;
    }

    for (const color of Object.keys(rates)) {
      const target = Math.min(rates[color], TARGET_CAP[color]);
      liveCounts[color] = countLive(color);
      if (liveCounts[color] < target && Math.random() < rates[color] * dt) {
        const pool = edgePaths
          .map((e, i) => (e.color === color ? i : -1))
          .filter((i) => i >= 0);
        if (pool.length) {
          const idx = pool[Math.floor(Math.random() * pool.length)];
          particles.push({
            idx,
            t: 0,
            speed: (140 + Math.random() * 80) / edgePaths[idx].len,
            color,
          });
        }
      }
    }

    for (let i = particles.length - 1; i >= 0; i--) {
      const p = particles[i];
      p.t += p.speed * dt;
      if (p.t >= 1) {
        particles.splice(i, 1);
        continue;
      }
      const e = edgePaths[p.idx];
      const pos = e.pathEl.getPointAtLength(p.t * e.len);
      const c = getCircle(i);
      c.setAttribute("cx", pos.x);
      c.setAttribute("cy", pos.y);
      c.setAttribute("fill", COLORS[p.color]);
      c.setAttribute("opacity", String(0.35 + 0.55 * Math.sin(Math.PI * p.t)));
    }
    // hide unused circles
    for (let i = particles.length; i < circles.length; i++)
      circles[i].setAttribute("opacity", "0");
    requestAnimationFrame(frame);
  }

  // Real query pulses (run-3 W3/W6): one-shot particles along the
  // table -> Basin SQL edges when a query actually runs. Particles on
  // this map always mean real events.
  function pulseSqlEdges(fromCards) {
    const pool = edgePaths
      .map((e, i) =>
        e.to === "e_sql" && (!fromCards || fromCards.includes(e.from)) ? i : -1)
      .filter((i) => i >= 0);
    for (const idx of pool) {
      particles.push({
        idx,
        t: Math.random() * 0.35, // stagger so the burst reads as a sweep
        speed: (200 + Math.random() * 90) / edgePaths[idx].len,
        color: "query",
      });
    }
  }
  window.__flowvizQueryPulse = (cardIds) => pulseSqlEdges(cardIds);

  // ------------------------------------------------------------------
  // LIVE: stats, toggle, ticker, console
  // ------------------------------------------------------------------

  const $ = (id) => document.getElementById(id);
  const fmt = (n) => {
    if (n == null) return "\u2013";
    if (n >= 1e9) return (n / 1e9).toFixed(1) + "B";
    if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
    return String(n);
  };

  const fmtAge = (s) => (s >= 90 ? Math.round(s / 60) + "m" : Math.round(s) + "s");
  const usd4 = (v) => (v == null ? "n/a" : "$" + v.toFixed(4));

  let prevSeen = null;
  let prevTs = null;
  let emaRate = 0;

  async function pollStats() {
    try {
      const r = await fetch("/api/stats", { cache: "no-store" });
      const d = await r.json();
      const bsky = d.bsky || {};
      const ticker = d.ticker || {};
      const seen = (bsky.seen || 0) + (ticker.lan || 0);
      const now = Date.now();
      if (prevSeen !== null && prevTs) {
        // Clamp at zero: a DO restart can reload older counters, which must
        // never read as negative throughput.
        const inst = Math.max(0, seen - prevSeen) / Math.max((now - prevTs) / 1000, 0.5);
        emaRate = emaRate === 0 ? inst : emaRate * 0.6 + inst * 0.4;
      }
      prevSeen = seen;
      prevTs = now;
      $("stat-rate").textContent = emaRate < 1 && emaRate > 0 ? emaRate.toFixed(1) : String(Math.round(emaRate));

      // Feed staleness: if the ticker has not received anything for five
      // minutes, say so in its title instead of leaving old lines that
      // look live (a stalled feed was the drill-through failure class).
      const tickLast = Number(ticker.lastTs || 0);
      const feedTitle = document.querySelector("#ticker .ticker-title");
      if (feedTitle) {
        const feedAge = tickLast ? Math.round((Date.now() - tickLast) / 1000) : null;
        if (feedAge !== null && feedAge > 300) {
          feedTitle.textContent = `live events - stalled, last event ${fmtAge(feedAge)} ago`;
          feedTitle.classList.add("stale");
        } else {
          feedTitle.textContent = "live events";
          feedTitle.classList.remove("stale");
        }
      }

      // Bluesky particle rate follows the live firehose; LAN follows relay volume.
      rates.blue = bsky.enabled ? Math.max(2.5, Math.min(emaRate, 40)) : 0.25;
      rates.green = Math.max(0.7, Math.min(emaRate * 0.6, 30));
      rates.orange = 0.35;

      // toggle state
      const cb = $("bsky-toggle");
      if (document.activeElement !== cb && !cb.dataset.busy) cb.checked = !!bsky.enabled;
      const lbl = $("bsky-state");
      lbl.textContent = bsky.enabled
        ? (bsky.connected ? "Bluesky: connected" : "Bluesky: reconnecting")
        : "Bluesky: paused";
      lbl.className = "toggle-label " + (bsky.enabled ? "on" : "off");

      // Header stats (W3): freshness, cost/day, compressed bytes/row and
      // the investigations unread badge. Server-computed; this renders.
      const h = d.header || {};
      if (h.freshness) {
        const age = h.freshness.worstAgeSec;
        const el = $("stat-fresh");
        if (el) {
          el.textContent = age == null ? "--" : fmtAge(age);
          el.classList.remove("fresh-warn", "fresh-bad");
          if (age != null) {
            if (age > 600) el.classList.add("fresh-bad");
            else if (age > 300) el.classList.add("fresh-warn");
          }
          const per = Object.entries(h.freshness.perTable || {})
            .map(([id, a]) => `${id}: ${a == null ? "no rows in the last hour" : fmtAge(a)}`)
            .join("\n");
          const wifi = h.freshness.wifiPollerAgeSec;
          const wifiLine =
            wifi === undefined
              ? ""
              : `\nwifi poller: newest wifi_client row ${wifi == null ? "not found in the last 20 minutes (stale)" : fmtAge(wifi)} old`;
          $("stat-fresh-box").title = per + wifiLine + "\n(newest-row age, probed every 15 min)";
        }
      }
      if (h.cost) {
        const el = $("stat-cost");
        if (el) {
          el.textContent =
            h.cost.perDayUsd == null
              ? "--"
              : "$" +
                (h.cost.perDayUsd < 0.01
                  ? h.cost.perDayUsd.toFixed(4)
                  : h.cost.perDayUsd.toFixed(2));
          const b = h.cost.breakdown || {};
          $("stat-cost-box").title =
            `Basin SQL scans: ${usd4(b.scan.usdPerDay)} (${fmt(b.scan.avgBytesPerDay)} B/day avg; $0.0025/GB, first 10 GB/mo free)\n` +
            `Workers AI: ${usd4(b.ai.usdPerDay)} (${Math.round(b.ai.avgNeuronsPerDay || 0)} neurons/day avg; 10k/day free)\n` +
            `R2 storage: ${usd4(b.storage.usdPerDay)} (${fmt(b.storage.bytesPerDay)} B/day growth; $0.015/GB-mo)\n` +
            `trailing 7-day averages; no clusters, no idle capacity`;
        }
      }
      if (h.compression) {
        const el = $("stat-byterow");
        if (el) {
          const pct = h.compression.warehousePercentRaw;
          el.textContent = pct == null ? "--" : (pct < 10 ? pct.toFixed(1) : Math.round(pct)) + "%";
          const pt = Object.entries(h.compression.perTable || {})
            .map(([id, s]) => {
              const raw = s.rawBytesPerRow;
              const sto = s.bytesPerRow;
              const p = raw && sto != null ? (sto / raw) * 100 : null;
              const note =
                p != null && p > 100 ? " (small-file footer tax until compaction merges commits)" : "";
              return `${id}: ${raw ? Math.round(raw) + " B raw" : "raw n/a"} -> ${sto == null ? "n/a" : Math.round(sto) + " B stored"}${p != null ? ` (${Math.round(p)}%${note})` : ""}`;
            })
            .join("\n");
          $("stat-byterow-box").title =
            "warehouse: stored bytes vs the same rows serialized as JSON\n" +
            pt +
            "\nmethod: 30-row JSON sample vs Iceberg snapshot bytes, hourly, weighted by storage growth; est";
        }
      }
      if (h.unread != null) {
        const badge = $("inbox-badge");
        if (badge) {
          if (h.unread > 0) {
            badge.textContent = String(Math.min(h.unread, 99));
            badge.classList.remove("hidden");
          } else badge.classList.add("hidden");
        }
      }
    } catch {
      /* stats are best-effort */
    }
  }

  // ---- Bluesky toggle ----

  const toggleEl = $("bsky-toggle");
  toggleEl.addEventListener("change", async () => {
    toggleEl.dataset.busy = "1";
    toggleEl.disabled = true;
    try {
      const r = await fetch("/api/bsky/toggle", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: toggleEl.checked }),
      });
      const st = await r.json();
      toggleEl.checked = !!st.enabled;
      $("bsky-state").textContent = st.enabled ? "Bluesky: connected" : "Bluesky: paused";
      $("bsky-state").className = "toggle-label " + (st.enabled ? "on" : "off");
    } catch {
      toggleEl.checked = !toggleEl.checked;
    } finally {
      toggleEl.disabled = false;
      delete toggleEl.dataset.busy;
    }
  });

  // ---- ticker (WebSocket, SSE fallback) ----

  const tickerList = $("ticker-list");

  const escapeHtml = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));

  // W4 popup: click a ticker line to see the full archive row (human
  // fields plus raw JSON), or the honest fallback when there is no id
  // yet or the row has aged out.
  function openEventPopup(evInfo) {
    const modal = $("event-modal");
    const body = $("event-modal-body");
    if (!modal || !body) return;
    const lineAgeSec = evInfo.tsMs ? Math.max(0, Math.round((Date.now() - evInfo.tsMs) / 1000)) : null;
    const ageNote = lineAgeSec === null ? "" : ` (this line is ${fmtAge(lineAgeSec)} old)`;
    if (popupRetryTimer) {
      clearTimeout(popupRetryTimer);
      popupRetryTimer = null;
    }
    $("event-modal-title").textContent = `event detail: ${String(evInfo.kind || "event")}`;
    if (!evInfo.id) {
      body.innerHTML =
        `<div class="event-note">This ticker line has no event id: its event predates the drill-through plumbing. ` +
        `What the ticker holds: <b>${escapeHtml(evInfo.text || "")}</b></div>`;
      modal.classList.remove("hidden");
      return;
    }
    body.innerHTML = `<div class="event-note">looking up the archive row${ageNote}...</div>`;
    modal.classList.remove("hidden");
    fetch(
      `/api/event/${encodeURIComponent(evInfo.id)}?kind=${encodeURIComponent(String(evInfo.kind || ""))}`,
      { cache: "no-store" },
    )
      .then((r) => r.json())
      .then((d) => {
        if (d && d.found && d.row) {
          body.innerHTML = "";
          const tbl = document.createElement("table");
          for (const [k, v] of Object.entries(d.row)) {
            const tr = document.createElement("tr");
            const th = document.createElement("th");
            th.textContent = k;
            const td = document.createElement("td");
            td.textContent = v == null ? "NULL" : typeof v === "object" ? JSON.stringify(v) : String(v);
            tr.append(th, td);
            tbl.appendChild(tr);
          }
          const note = document.createElement("div");
          note.className = "event-note";
          note.textContent = `from ${d.table}; full row as stored (behind Access, same stance as evidence)`;
          const raw = document.createElement("div");
          raw.className = "event-raw";
          raw.textContent = JSON.stringify(d.row, null, 2);
          body.append(tbl, note, raw);
        } else {
          let why = (d && d.note) || "archive row not found";
          if (lineAgeSec !== null && lineAgeSec < 10 * 60) {
            // Root cause (run-5, live-proven 2026-10-26): the ticker is
            // real-time but the warehouse row only becomes queryable after
            // the pipeline commits it (1-2 min steady state, longer while
            // table metadata is bloated). A fresh line that returns
            // not-found is racing the commit, not missing.
            why =
              "this event was ingested " +
              fmtAge(lineAgeSec) +
              " ago and the archive row is still committing to the warehouse (pipeline lag is typically 1-2 minutes). Retrying...";
            body.innerHTML =
              `<div class="event-note">${escapeHtml(why)} ` +
              `What the ticker holds: <b>${escapeHtml(evInfo.text || "")}</b></div>`;
            const retryBtn = document.createElement("button");
            retryBtn.className = "btn small";
            retryBtn.textContent = "retry now";
            retryBtn.style.marginTop = "6px";
            retryBtn.addEventListener("click", () => {
              if (popupRetryTimer) {
                clearTimeout(popupRetryTimer);
                popupRetryTimer = null;
              }
              openEventPopup(evInfo);
            });
            body.appendChild(retryBtn);
            evInfo._retries = (evInfo._retries || 0) + 1;
            if (evInfo._retries <= 5) {
              popupRetryTimer = setTimeout(() => {
                popupRetryTimer = null;
                if (!modal.classList.contains("hidden")) openEventPopup(evInfo);
              }, 30_000);
            }
          } else {
            if (lineAgeSec !== null && lineAgeSec > 110 * 60) {
              why =
                "this line is outside the 2-hour lookup window (" +
                fmtAge(lineAgeSec) +
                " old). If the live events feed has stalled, refresh the page: stalled feeds leave old lines on screen.";
            }
            body.innerHTML =
              `<div class="event-note">${escapeHtml(why)}. ` +
              `What the ticker holds: <b>${escapeHtml(evInfo.text || "")}</b></div>`;
          }
        }
      })
      .catch(() => {
        body.innerHTML = `<div class="event-note">lookup failed; try again.</div>`;
      });
  }

  const TICKER_LINE_TTL_MS = 15 * 60_000;
  // Pipeline commit lag: a row becomes queryable ~1-2 minutes after the
  // ticker shows it (live-proven, run-5). Lines younger than this are
  // "pending": their timestamp tints orange until the archive can
  // answer, and clicks resolve as soon as the row is committed.
  const COMMIT_LAG_MS = 2 * 60_000;
  let popupRetryTimer = null;

  function markTickerCommitState() {
    const now = Date.now();
    for (const li of Array.from(tickerList.children)) {
      const age = now - Number(li.dataset.tsMs || 0);
      li.classList.toggle("pending", age < COMMIT_LAG_MS);
    }
  }

  function expireTickerLines() {
    const cutoff = Date.now() - TICKER_LINE_TTL_MS;
    for (const li of Array.from(tickerList.children)) {
      if (Number(li.dataset.tsMs || 0) < cutoff) li.remove();
    }
  }

  function addTicker(ev) {
    const kind = String(ev.kind || "event");
    const text = String(ev.text || "");
    const evTsMs = Date.parse(ev.ts || "") || Date.now();
    // Lines expire after 15 minutes: a stalled feed empties visibly
    // instead of leaving old-but-clickable lines (run-4 lesson).
    expireTickerLines();
    // W10 (fixed): collapse consecutive same-kind AND same-text events
    // within a 60 s window. Keying on kind alone merged distinct HA
    // sensors into one line whose visible text then disagreed with its
    // hidden lookup id; the visible text now updates with every merge.
    const first = tickerList.firstElementChild;
    if (
      first &&
      first.dataset.kind === kind &&
      first.dataset.text === text &&
      evTsMs - Number(first.dataset.tsMs || 0) <= 60_000
    ) {
      const n = (Number(first.dataset.count || 1) || 1) + 1;
      first.dataset.count = String(n);
      first.dataset.tsMs = String(evTsMs);
      first.dataset.text = text;
      if (ev.event_id) first.dataset.eventId = String(ev.event_id);
      const txtSpan = first.querySelector(".ticker-text");
      if (txtSpan) {
        txtSpan.textContent = text;
        txtSpan.title = text;
      }
      const countEl = first.querySelector(".ticker-count");
      if (countEl) countEl.textContent = "x" + n;
      const tsEl = first.querySelector(".ticker-ts");
      if (tsEl) tsEl.textContent = (ev.ts || "").slice(11, 19);
      return;
    }
    const li = document.createElement("li");
    li.dataset.kind = kind;
    li.dataset.tsMs = String(evTsMs);
    li.dataset.text = String(ev.text || "");
    if (ev.event_id) li.dataset.eventId = String(ev.event_id);
    li.title = "click for the full archive row";
    const badge = document.createElement("span");
    badge.className = "badge " + (ev.source === "bluesky" ? "bluesky" : "lan");
    badge.textContent = kind.slice(0, 18);
    const txt = document.createElement("span");
    txt.className = "ticker-text";
    txt.textContent = String(ev.text || "");
    txt.title = String(ev.text || "");
    const count = document.createElement("span");
    count.className = "ticker-count";
    const ts = document.createElement("span");
    ts.className = "ticker-ts";
    ts.textContent = (ev.ts || "").slice(11, 19);
    li.append(badge, txt, count, ts);
    li.addEventListener("click", () => {
      openEventPopup({
        id: li.dataset.eventId || "",
        kind,
        text: li.dataset.text || "",
        tsMs: Number(li.dataset.tsMs || 0),
      });
    });
    tickerList.prepend(li);
    while (tickerList.children.length > 40) tickerList.removeChild(tickerList.lastChild);
  }

  function connectTicker() {
    let tries = 0;
    let ws = null;
    const open = () => {
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      ws = new WebSocket(`${proto}//${location.host}/ws`);
      ws.onmessage = (m) => {
        try {
          const d = JSON.parse(m.data);
          if (d.type === "hello") (d.recent || []).forEach(addTicker);
          if (d.type === "ticker") (d.events || []).forEach(addTicker);
        } catch { /* ignore */ }
      };
      ws.onclose = () => {
        tries += 1;
        if (tries <= 5) setTimeout(open, 1200 * tries);
        else startSse();
      };
      ws.onerror = () => { try { ws.close(); } catch {} };
    };
    open();
  }

  function startSse() {
    try {
      const es = new EventSource("/events");
      es.onmessage = (m) => {
        try { addTicker(JSON.parse(m.data)); } catch { /* ignore */ }
      };
    } catch { /* SSE unavailable */ }
  }

  connectTicker();

  // ---- ticker resize (W5): drag the handle; double-click snaps ----
  const tickerHandle = $("ticker-handle");
  if (tickerHandle) {
    const applyTickerH = (h) => {
      const v = Math.max(
        96,
        Math.min(Math.round(window.innerHeight * 0.8), Math.round(h)),
      );
      document.documentElement.style.setProperty("--ticker-h", v + "px");
      try {
        localStorage.setItem("ticker-h", String(v));
      } catch {}
      scheduleLayout();
    };
    try {
      const saved = parseInt(localStorage.getItem("ticker-h") || "", 10);
      if (Number.isFinite(saved) && saved >= 96)
        document.documentElement.style.setProperty("--ticker-h", saved + "px");
    } catch {}
    let dragging = false;
    tickerHandle.addEventListener("pointerdown", (e) => {
      dragging = true;
      tickerHandle.classList.add("dragging");
      tickerHandle.setPointerCapture(e.pointerId);
      e.preventDefault();
    });
    tickerHandle.addEventListener("pointermove", (e) => {
      if (!dragging) return;
      applyTickerH(window.innerHeight - e.clientY);
    });
    const endDrag = () => {
      if (!dragging) return;
      dragging = false;
      tickerHandle.classList.remove("dragging");
    };
    tickerHandle.addEventListener("pointerup", endDrag);
    tickerHandle.addEventListener("pointercancel", endDrag);
    // Double-click: compact (150px) <-> expanded (~half viewport).
    // Presentation mode keeps its own 96px via CSS specificity.
    tickerHandle.addEventListener("dblclick", () => {
      const cur = parseInt(
        (getComputedStyle(document.documentElement).getPropertyValue("--ticker-h") || "150").trim(),
        10,
      );
      applyTickerH(Number.isFinite(cur) && cur > 200 ? 150 : window.innerHeight * 0.5);
    });
  }

  // ---- rows-in-24h header stat: server-cached aggregate (N tabs cost one
  // query set), skipped while the tab is hidden, backed off after failures ----
  let rowsFails = 0;
  async function pollRows() {
    if (document.hidden) {
      setTimeout(pollRows, 30000);
      return;
    }
    try {
      const r = await fetch("/api/rows", { cache: "no-store" });
      const d = await r.json();
      $("stat-rows").textContent = d.rows == null ? "\u2013" : fmt(d.rows);
      rowsFails = 0;
    } catch {
      rowsFails += 1;
    } finally {
      setTimeout(pollRows, rowsFails >= 3 ? 600000 : 60000);
    }
  }

  // ---- tabs (W8): FlowViz | Investigations | Ask ----

  const TABS = ["flow", "investigations", "ask"];
  const tabBtns = Array.from(document.querySelectorAll("#tabs .tab"));

  function switchTab(name) {
    if (!TABS.includes(name)) return;
    document.body.dataset.tab = name;
    for (const btn of tabBtns) btn.classList.toggle("active", btn.dataset.tab === name);
    for (const view of document.querySelectorAll(".tab-view"))
      view.classList.toggle("active", view.id === `tab-${name}`);
    try {
      localStorage.setItem("flowviz-tab", name);
    } catch {}
    document.dispatchEvent(new CustomEvent("flowviz:tab", { detail: { name } }));
    if (name === "flow") scheduleLayout();
  }
  window.__flowvizSwitchTab = switchTab;
  // The wire that shipped missing once (run-4 bug 1) - asserted by
  // scripts/test-wiring.py now.
  for (const btn of tabBtns) btn.addEventListener("click", () => switchTab(btn.dataset.tab));

  // ---- Ask tab input mode (AI | SQL) ----

  function setAskMode(mode) {
    const ai = mode === "ai";
    $("mode-ai").classList.toggle("active", ai);
    $("mode-sql").classList.toggle("active", !ai);
    $("ask-input").classList.toggle("hidden", !ai);
    $("ask-submit").classList.toggle("hidden", !ai);
    $("sql-input").classList.toggle("hidden", ai);
    $("sql-run").classList.toggle("hidden", ai);
    $("ask-chips").classList.toggle("hidden", !ai);
    $("sql-chips").classList.toggle("hidden", ai);
    $("ask-body").classList.toggle("hidden", !ai);
    $("sql-result").classList.toggle("hidden", ai);
    try {
      localStorage.setItem("flowviz-ask-mode", mode);
    } catch {}
  }
  window.__flowvizAskMode = setAskMode;
  $("mode-ai").addEventListener("click", () => setAskMode("ai"));
  $("mode-sql").addEventListener("click", () => setAskMode("sql"));

  // ---- SQL console (the Ask tab's SQL mode) ----

  const CHIPS = [
    { label: "Likes so far (24h)",
      sql: "SELECT COUNT(*) AS likes FROM bsky.bsky_like WHERE __ingest_ts >= now() - INTERVAL '1 day'" },
    { label: "Top post languages (24h)",
      sql: "SELECT langs, COUNT(*) AS c FROM bsky.bsky_post WHERE langs IS NOT NULL AND __ingest_ts >= now() - INTERVAL '1 day' GROUP BY langs ORDER BY c DESC LIMIT 10" },
    { label: "Events by type (24h)",
      sql: "SELECT 'post' AS event_type, COUNT(*) AS c FROM bsky.bsky_post WHERE __ingest_ts >= now() - INTERVAL '1 day' UNION ALL SELECT 'like', COUNT(*) FROM bsky.bsky_like WHERE __ingest_ts >= now() - INTERVAL '1 day' UNION ALL SELECT 'repost', COUNT(*) FROM bsky.bsky_repost WHERE __ingest_ts >= now() - INTERVAL '1 day' UNION ALL SELECT 'follow', COUNT(*) FROM bsky.bsky_follow WHERE __ingest_ts >= now() - INTERVAL '1 day' UNION ALL SELECT 'block', COUNT(*) FROM bsky.bsky_block WHERE __ingest_ts >= now() - INTERVAL '1 day' LIMIT 10" },
    { label: "Noisiest hosts (24h)",
      sql: "SELECT host, COUNT(*) AS c FROM homelab.syslog WHERE __ingest_ts >= now() - INTERVAL '1 day' GROUP BY host ORDER BY c DESC LIMIT 10" },
    { label: "Hottest room (24h)",
      sql: "SELECT entity_id, MAX(value) AS max_value FROM ha.ha_sensor_readings WHERE entity_id LIKE '%temp%' AND __ingest_ts >= now() - INTERVAL '1 day' GROUP BY entity_id ORDER BY max_value DESC LIMIT 10" },
    { label: "Lights on (recent)",
      sql: "SELECT DISTINCT entity_id FROM ha.ha_state_changes WHERE event_type = 'light' AND state = 'on' AND __ingest_ts >= now() - INTERVAL '1 day' LIMIT 20" },
    { label: "Most-queried domains (24h)",
      sql: "SELECT COALESCE(json_get_str(fields, 'domain'), json_get_str(json_get_str(fields), 'domain')) AS domain, COUNT(*) AS c FROM homelab.dns_queries WHERE __ingest_ts >= now() - INTERVAL '1 day' GROUP BY domain ORDER BY c DESC LIMIT 10" },
    { label: "Zone requests by status (1h)",
      sql: "SELECT \"EdgeResponseStatus\" AS status, COUNT(*) AS c FROM cfzone.http_requests WHERE __ingest_ts >= now() - INTERVAL '1 hour' GROUP BY \"EdgeResponseStatus\" ORDER BY c DESC LIMIT 10" },
    { label: "Worker events by outcome (1h)",
      sql: "SELECT \"Outcome\", COUNT(*) AS c FROM cfwork.workers_trace_events WHERE __ingest_ts >= now() - INTERVAL '1 hour' GROUP BY \"Outcome\" ORDER BY c DESC LIMIT 10" },
    { label: "Show databases",
      sql: "SHOW DATABASES" },
    { label: "Show tables in bsky",
      sql: "SHOW TABLES IN bsky" },
  ];

  const chipsEl = $("sql-chips");
  for (const chip of CHIPS) {
    const b = document.createElement("button");
    b.className = "chip";
    b.type = "button";
    b.textContent = chip.label;
    b.addEventListener("click", () => {
      $("sql-input").value = chip.sql;
      runSql();
    });
    chipsEl.appendChild(b);
  }

  async function runSql() {
    const q = $("sql-input").value;
    const out = $("sql-result");
    const runBtn = $("sql-run");
    if (!q.trim()) return;
    runBtn.disabled = true;
    out.innerHTML = `<div class="sql-empty">running...</div>`;
    try {
      const r = await fetch("/api/sql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: q }),
      });
      const d = await r.json();
      if (d && d.success && window.__flowvizQueryPulse) {
        // A real query just ran: sweep the table -> Basin SQL edges.
        window.__flowvizQueryPulse(null);
      }
      out.innerHTML = "";
      if (d.success && d.result) {
        const rows = d.result.rows || [];
        const schema = d.result.schema || [];
        const m = d.result.metrics || {};
        const meta = document.createElement("div");
        meta.className = "sql-metrics";
        meta.textContent =
          `${rows.length} row(s)` +
          (m.bytes_scanned != null ? ` - ${fmt(m.bytes_scanned)} bytes scanned` : "") +
          (m.files_scanned != null ? ` - ${m.files_scanned} file(s)` : "");
        out.appendChild(meta);
        if (!rows.length) {
          out.appendChild(Object.assign(document.createElement("div"), { className: "sql-empty", textContent: "no rows" }));
          return;
        }
        const table = document.createElement("table");
        const thead = document.createElement("thead");
        const hr = document.createElement("tr");
        for (const col of schema) {
          const th = document.createElement("th");
          th.textContent = col.name;
          hr.appendChild(th);
        }
        if (!schema.length) for (const k of Object.keys(rows[0])) {
          const th = document.createElement("th");
          th.textContent = k;
          hr.appendChild(th);
        }
        thead.appendChild(hr);
        table.appendChild(thead);
        const tbody = document.createElement("tbody");
        for (const row of rows.slice(0, 200)) {
          const tr = document.createElement("tr");
          const vals = schema.length ? schema.map((c) => row[c.name]) : Object.values(row);
          for (const v of vals) {
            const td = document.createElement("td");
            td.textContent = v == null ? "NULL" : typeof v === "object" ? JSON.stringify(v) : String(v);
            tr.appendChild(td);
          }
          tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        out.appendChild(table);
      } else {
        const err = document.createElement("div");
        const code = d.errors && d.errors[0] && d.errors[0].code;
        if (code === 503) {
          err.className = "sql-empty";
          err.textContent =
            "Console is waiting for setup: mint the R2 API token and run scripts/setup-basin.sh (docs/DEPLOY.md, Tokens section).";
        } else {
          err.className = "sql-error";
          const msg = (d.errors && d.errors[0] && d.errors[0].message) || "Unknown error";
          err.textContent = msg + (code ? ` (code ${code})` : "");
        }
        out.appendChild(err);
      }
    } catch {
      out.innerHTML = `<div class="sql-error">request failed</div>`;
    } finally {
      runBtn.disabled = false;
    }
  }

  $("sql-run").addEventListener("click", runSql);
  $("sql-input").addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      runSql();
    }
  });

  // ---- flow map highlight hook (Ask scoping) ----

  // Lit edges stay visible while the rest dim, so clicking a table card in
  // the Ask panel shows the data path behind it.
  window.__flowvizHighlight = (cardId) => {
    document.body.classList.toggle("scoped", Boolean(cardId));
    for (const e of edgePaths) {
      const lit = cardId && (e.from === cardId || e.to === cardId);
      e.pathEl.classList.toggle("edge-lit", Boolean(lit));
    }
  };

  // ---- keyboard shortcuts ----

  const eventModal = $("event-modal");
  if (eventModal) {
    $("event-modal-close").addEventListener("click", () => eventModal.classList.add("hidden"));
    eventModal.addEventListener("click", (e) => {
      if (e.target === eventModal) eventModal.classList.add("hidden");
    });
  }

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      const m = $("event-modal");
      if (m) m.classList.add("hidden");
    }
    const tag = (e.target && e.target.tagName || "").toLowerCase();
    if (tag === "textarea" || tag === "input") return;
    if (["1", "2", "3"].includes(e.key)) switchTab(TABS[Number(e.key) - 1]);
    if (e.key === "p") document.body.classList.toggle("presentation");
    if (e.key === "f") {
      if (document.fullscreenElement) document.exitFullscreen();
      else document.documentElement.requestFullscreen().catch(() => {});
    }
  });

  // ------------------------------------------------------------------
  // boot
  // ------------------------------------------------------------------

  renderColumns();
  layoutEdges();
  requestAnimationFrame(frame);
  // Live re-layout whenever any column scrolls (Tables is the scrollable one)
  // or the window resizes, so edges and dots always track real card positions.
  for (const col of columnsEl.children) {
    col.addEventListener("scroll", scheduleLayout, { passive: true });
  }
  window.addEventListener("resize", scheduleLayout);
  new MutationObserver(() => scheduleLayout())
    .observe(document.body, { attributes: true, attributeFilter: ["class"] });

  pollStats();
  setInterval(pollStats, 3000);
  pollRows();
  markTickerCommitState();
  setInterval(markTickerCommitState, 20_000);
  // W8 boot: restore the last input mode and tab.
  try {
    setAskMode(localStorage.getItem("flowviz-ask-mode") === "sql" ? "sql" : "ai");
  } catch {
    setAskMode("ai");
  }
  let savedTab = null;
  try {
    savedTab = localStorage.getItem("flowviz-tab");
  } catch {}
  switchTab(TABS.includes(savedTab) ? savedTab : "flow");
})();
