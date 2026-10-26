/* Ask panel + investigation inbox (plan sections 5 and 6).
 * Vanilla JS, no build step. All rendering is driven by server-validated
 * chart specs and chartData computed from query results; this file never
 * evaluates model-generated code. */
window.FlowvizAsk = (() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  // Map the flow map's card ids to catalogue table ids (public/app.js COLUMNS).
  const CARD_TO_TABLE = {
    t_post: "bsky.bsky_post", t_like: "bsky.bsky_like", t_repost: "bsky.bsky_repost",
    t_follow: "bsky.bsky_follow", t_block: "bsky.bsky_block",
    t_ha_state: "ha.ha_state_changes", t_ha_sensor: "ha.ha_sensor_readings",
    t_syslog: "homelab.syslog", t_metrics: "homelab.host_metrics",
    t_udev: "homelab.unifi_devices", t_ucli: "homelab.unifi_clients",
    t_dnsq: "homelab.dns_queries",
    t_zhttp: "cfzone.http_requests", t_zfw: "cfzone.firewall_events", t_zdns: "cfzone.dns_logs",
    t_wt: "cfwork.workers_trace_events",
  };

  const TABLE_TO_CARD = {};
  for (const [card, table] of Object.entries(CARD_TO_TABLE)) TABLE_TO_CARD[table] = card;

  const session = { tableScope: null, fromUTC: null, toUTC: null, lineage: [] };
  let catalogData = null;
  let lastSelection = null;

  function awst(ts) {
    try {
      return new Date(ts).toLocaleString("en-AU", {
        timeZone: "Australia/Perth",
        day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit",
      });
    } catch {
      return String(ts);
    }
  }

  async function jfetch(url, opts) {
    const r = await fetch(url, opts);
    return r.json().catch(() => ({}));
  }

  function post(url, body) {
    return jfetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  // ------------------------------------------------------------------
  // catalog + chips
  // ------------------------------------------------------------------

  async function loadCatalog() {
    catalogData = await jfetch("/api/catalog");
    if (!catalogData || !catalogData.questions) return;
    const holder = $("ask-chips");
    holder.innerHTML = "";
    for (const q of catalogData.questions) {
      const b = document.createElement("button");
      b.className = "chip" + (q.status === "available" ? "" : " gated");
      b.type = "button";
      b.textContent = q.question;
      b.title =
        q.status === "available"
          ? "verified question"
          : `gated: ${q.statusNote || q.status}`;
      if (q.status === "available") {
        b.addEventListener("click", () => ask(q.question));
      } else {
        b.addEventListener("click", () => {
          note(`"${q.question}" is disabled: ${q.statusNote || q.status}`);
        });
      }
      holder.appendChild(b);
    }
  }

  function note(text) {
    const n = $("ask-note");
    n.textContent = text;
    n.classList.remove("hidden");
    setTimeout(() => n.classList.add("hidden"), 6000);
  }

  // ------------------------------------------------------------------
  // scope: card clicks from the flow map
  // ------------------------------------------------------------------

  document.addEventListener("flowviz:card", (ev) => {
    const { id, label } = ev.detail || {};
    const table = CARD_TO_TABLE[id];
    if (!table) return; // only table cards scope questions
    if (session.tableScope === table) {
      session.tableScope = null;
      if (window.__flowvizHighlight) window.__flowvizHighlight(null);
    } else {
      session.tableScope = table;
      if (window.__flowvizHighlight) window.__flowvizHighlight(id);
    }
    renderSession();
  });

  function renderSession() {
    const holder = $("ask-session");
    holder.innerHTML = "";
    if (session.tableScope) {
      holder.appendChild(chipEl(`scoped: ${session.tableScope}`, () => {
        session.tableScope = null;
        if (window.__flowvizHighlight) window.__flowvizHighlight(null);
        renderSession();
      }));
    }
    if (session.fromUTC && session.toUTC) {
      holder.appendChild(
        chipEl(`window: ${awst(session.fromUTC)} to ${awst(session.toUTC)} AWST`, () => {
          session.fromUTC = null;
          session.toUTC = null;
          renderSession();
        }),
      );
    }
  }

  function chipEl(text, onRemove) {
    const c = document.createElement("span");
    c.className = "scope-chip";
    c.textContent = text;
    const x = document.createElement("button");
    x.className = "scope-x";
    x.textContent = "x";
    x.title = "remove";
    x.addEventListener("click", onRemove);
    c.appendChild(x);
    return c;
  }

  // ------------------------------------------------------------------
  // the ask flow
  // ------------------------------------------------------------------

  function ask(question) {
    if (!question) return;
    $("ask-input").value = question;
    session.lineage = [...session.lineage, question].slice(-3);
    const body = {
      question,
      session: {
        tableScope: session.tableScope,
        fromUTC: session.fromUTC,
        toUTC: session.toUTC,
        lineage: session.lineage,
      },
    };
    openPanel();
    setBusy(question);
    post("/api/ask", body).then((d) => render(d, question)).catch(() =>
      render({ state: "failed", notes: ["request failed"] }, question),
    );
  }

  function openPanel() {
    // W8: the Ask workspace is always mounted; make sure it is the
    // active view and that charts resize into the wider workspace.
    if (window.__flowvizSwitchTab) window.__flowvizSwitchTab("ask");
    setTimeout(() => window.FlowvizCharts && FlowvizCharts.resizeAll(), 30);
  }

  function setBusy(question) {
    const out = $("ask-body");
    out.innerHTML = "";
    const d = document.createElement("div");
    d.className = "ask-busy";
    d.textContent = `asking: ${question}`;
    out.appendChild(d);
  }

  const stateLabels = {
    answered: "answer",
    ambiguous: "clarify",
    unsupported: "unsupported",
    empty: "no rows",
    stale: "stale data",
    truncated: "truncated",
    failed: "failed",
    limited: "rate limited",
    "model-unavailable": "model unavailable",
    scenario: "scenario",
  };

  function render(d, question) {
    const out = $("ask-body");
    out.innerHTML = "";
    const head = document.createElement("div");
    head.className = "ask-state " + (d.state || "failed");
    head.textContent = stateLabels[d.state] || d.state || "?";
    out.appendChild(head);

    if (d.state === "ambiguous" && d.ambiguities?.length) {
      for (const a of d.ambiguities) {
        const b = document.createElement("button");
        b.className = "chip";
        b.textContent = a;
        b.addEventListener("click", () => ask(a));
        out.appendChild(b);
      }
    }

    // Unsupported questions get the nearest answerable chips as pivots
    // (plan 5.1: never a dead end). Verified questions are one click away.
    if (d.state === "unsupported" && catalogData?.questions) {
      const label = document.createElement("div");
      label.className = "ask-note";
      label.textContent = "Closest answerable questions:";
      out.appendChild(label);
      for (const q of catalogData.questions) {
        if (q.status !== "available") continue;
        const b = document.createElement("button");
        b.className = "chip";
        b.textContent = q.question;
        b.addEventListener("click", () => ask(q.question));
        out.appendChild(b);
      }
    }

    if (d.state === "scenario") {
      renderTimeline(d.scenarioTimeline || [], out);
      renderNotes(d.notes || [], out);
      renderEvidence(d.evidence || [], out);
      return;
    }

    // A real governed query just ran: pulse the flow map's query edges
    // for the primary table (run-3 W3/W6: particles mean real events).
    if (window.__flowvizQueryPulse && (d.state === "answered" || d.state === "scenario")) {
      const t = d.plan && d.plan.table;
      window.__flowvizQueryPulse(t && TABLE_TO_CARD[t] ? [TABLE_TO_CARD[t]] : null);
    }

    if (d.answer) {
      const a = document.createElement("div");
      a.className = "ask-answer";
      a.textContent = d.answer;
      out.appendChild(a);
    }
    if (d.numbers) {
      const nums = document.createElement("div");
      nums.className = "ask-nums";
      nums.textContent = Object.entries(d.numbers)
        .map(([k, v]) => `${k}: ${v}`)
        .join("   |   ");
      out.appendChild(nums);
    }
    if (d.freshness?.maxIngestTs) {
      const f = document.createElement("div");
      f.className = "ask-fresh";
      f.textContent = `latest ingested row (this table): ${awst(d.freshness.maxIngestTs)} AWST`;
      out.appendChild(f);
    }
    if (d.chart && d.chartData) renderChart(d, out);
    if (d.state === "empty") {
      const e = document.createElement("div");
      e.className = "ask-note";
      e.textContent =
        "No rows matched. If this window is recent, ingestion lag (1-2 minutes) or a pipeline gap could explain it: the coverage question distinguishes them.";
      out.appendChild(e);
    }
    renderNotes(d.notes || [], out);
    renderEvidence(d.evidence || [], out);
  }

  function renderNotes(notes, out) {
    if (!notes.length) return;
    const n = document.createElement("div");
    n.className = "ask-notes";
    for (const t of notes) {
      const li = document.createElement("div");
      li.textContent = "- " + t;
      n.appendChild(li);
    }
    out.appendChild(n);
  }

  // ------------------------------------------------------------------
  // chart rendering (fixed wrappers; see charts.js)
  // ------------------------------------------------------------------

  function renderChart(d, out) {
    const box = document.createElement("div");
    box.className = "chart-box";
    out.appendChild(box);
    const spec = d.chart;
    const data = d.chartData || [];
    if (spec.type === "time-series" || spec.type === "comparison") {
      FlowvizCharts.timeSeries(box, spec, data, d.baselineData);
      hookRefine(box, spec);
    } else if (spec.type === "ranked-bars") {
      FlowvizCharts.rankedBars(box, spec, data);
    } else if (spec.type === "coverage-grid") {
      FlowvizCharts.coverageGrid(box, spec, data);
    } else if (spec.type === "state-timeline") {
      renderStates(data, out);
      box.remove();
    } else {
      box.remove();
    }
    setTimeout(() => FlowvizCharts.resizeAll(), 30);
  }

  function hookRefine(box, spec) {
    // Brush a time range in the chart, then refine to that window.
    const btn = document.createElement("button");
    btn.className = "btn small hidden";
    btn.textContent = "refine to selected range";
    box.parentElement.insertBefore(btn, box.nextSibling);
    const ch = box.__echarts__;
    if (ch) {
      ch.on("dataZoom", () => {
        const opt = ch.getOption();
        const z = (opt.dataZoom && opt.dataZoom[0]) || {};
        lastSelection = null;
        if (z.startValue != null && z.endValue != null) {
          lastSelection = { from: z.startValue, to: z.endValue };
          btn.classList.remove("hidden");
        }
      });
    }
    btn.addEventListener("click", () => {
      if (!lastSelection) return;
      session.fromUTC = new Date(lastSelection.from).toISOString();
      session.toUTC = new Date(lastSelection.to).toISOString();
      renderSession();
      ask($("ask-input").value);
    });
  }

  function renderStates(rows, out) {
    const list = document.createElement("div");
    list.className = "state-list";
    for (const r of rows) {
      const row = document.createElement("div");
      row.className = "state-row";
      const name = document.createElement("span");
      name.textContent = r.entity_id;
      const st = document.createElement("span");
      st.className = "state-badge " + String(r.state);
      st.textContent = String(r.state);
      const age = document.createElement("span");
      age.className = "state-age";
      const mins = Math.round((Date.now() - Date.parse(r.ts)) / 60000);
      age.textContent =
        r.state === "unavailable"
          ? "unavailable (no change in window)"
          : `last change ${awst(r.ts)} AWST (${mins < 90 ? mins + " min" : Math.round(mins / 60) + " h"} ago)`;
      row.append(name, st, age);
      list.appendChild(row);
    }
    out.appendChild(list);
  }

  function renderTimeline(events, out) {
    const bySource = new Map();
    for (const ev of events) {
      if (!bySource.has(ev.source)) bySource.set(ev.source, []);
      bySource.get(ev.source).push(ev);
    }
    const wrap = document.createElement("div");
    wrap.className = "timeline";
    for (const [src, evs] of bySource) {
      const h = document.createElement("div");
      h.className = "tl-src " + src;
      h.textContent = src;
      wrap.appendChild(h);
      for (const ev of evs.slice(0, 60)) {
        const row = document.createElement("div");
        row.className = "tl-row";
        const t = document.createElement("span");
        t.className = "tl-ts";
        t.textContent = awst(ev.ingestTs || ev.ts);
        const who = document.createElement("span");
        who.className = "tl-actor";
        who.textContent = ev.actor || "";
        const what = document.createElement("span");
        what.className = "tl-what";
        what.textContent = ev.description;
        row.append(t, who, what);
        wrap.appendChild(row);
      }
    }
    if (!events.length) {
      const e = document.createElement("div");
      e.className = "ask-note";
      e.textContent = "No events in the fused window.";
      wrap.appendChild(e);
    }
    out.appendChild(wrap);
  }

  // ------------------------------------------------------------------
  // evidence: SQL + expandable rows
  // ------------------------------------------------------------------

  function renderEvidence(evidence, out) {
    if (!evidence.length) return;
    const holder = document.createElement("div");
    holder.className = "evidence";
    for (const ev of evidence) {
      const block = document.createElement("div");
      block.className = "evidence-block";

      const head = document.createElement("button");
      head.className = "evidence-head";
      head.textContent = `evidence: ${ev.kind} (${ev.rowCount} rows${ev.truncated ? ", truncated" : ""})`;
      head.addEventListener("click", () => {
        const body = block.querySelector(".evidence-body");
        body.classList.toggle("hidden");
        if (!body.classList.contains("hidden") && !body.dataset.loaded) loadRows(ev.id, body);
      });
      block.appendChild(head);

      const sql = document.createElement("pre");
      sql.className = "evidence-sql";
      sql.textContent = ev.sql;
      block.appendChild(sql);

      const copy = document.createElement("button");
      copy.className = "btn small";
      copy.textContent = "copy SQL";
      copy.addEventListener("click", () => {
        navigator.clipboard?.writeText(ev.sql);
        copy.textContent = "copied";
      });
      block.appendChild(copy);

      const body = document.createElement("div");
      body.className = "evidence-body hidden";
      block.appendChild(body);

      holder.appendChild(block);
    }
    out.appendChild(holder);
  }

  async function loadRows(id, holder) {
    const d = await jfetch(`/api/evidence/${id}/rows?offset=0&limit=100`);
    holder.dataset.loaded = "1";
    if (!d.rows) {
      holder.textContent = "rows snapshot unavailable (report store not configured)";
      return;
    }
    const t = document.createElement("table");
    const hr = document.createElement("tr");
    for (const c of d.schema || Object.keys(d.rows[0] || {})) {
      const th = document.createElement("th");
      th.textContent = typeof c === "string" ? c : c.name;
      hr.appendChild(th);
    }
    t.appendChild(hr);
    for (const r of d.rows) {
      const tr = document.createElement("tr");
      for (const v of Object.values(r)) {
        const td = document.createElement("td");
        td.textContent = v == null ? "NULL" : typeof v === "object" ? JSON.stringify(v) : String(v);
        tr.appendChild(td);
      }
      t.appendChild(tr);
    }
    holder.appendChild(t);
  }

  // ------------------------------------------------------------------
  // investigation inbox
  // ------------------------------------------------------------------

  async function refreshInbox() {
    const list = $("inbox-list");
    list.innerHTML = "";
    const d = await jfetch("/api/investigations");
    const reports = d.reports || [];
    if (!reports.length) {
      const e = document.createElement("div");
      e.className = "ask-note";
      e.textContent = d.note
        ? `inbox: ${d.note}`
        : "No investigations yet. The dns-volume detector reports here; a burst (roughly 900+ queries from one client in 10 minutes) triggers one.";
      list.appendChild(e);
      return;
    }
    for (const r of reports) {
      const row = document.createElement("button");
      row.className = "inbox-row";
      const cls = document.createElement("span");
      cls.className = "state-badge " + (r.classification || "open");
      cls.textContent = r.classification || r.status;
      const meta = document.createElement("span");
      meta.textContent = `${r.playbook} - ${awst(r.updated_at)} AWST`;
      row.append(cls, meta);
      row.addEventListener("click", () => openReport(r.id));
      list.appendChild(row);
    }
  }

  async function openReport(id) {
    const holder = $("inbox-report");
    holder.innerHTML = "";
    holder.classList.remove("hidden");
    $("inbox-list").classList.add("hidden");
    const r = await jfetch(`/api/investigations/${id}`);
    if (r.error) {
      holder.textContent = r.error;
      return;
    }
    const back = document.createElement("button");
    back.className = "btn small";
    back.textContent = "< back";
    back.addEventListener("click", () => {
      holder.classList.add("hidden");
      $("inbox-list").classList.remove("hidden");
    });
    holder.appendChild(back);

    const h = document.createElement("div");
    h.className = "report-head";
    const cls = document.createElement("span");
    cls.className = "state-badge " + r.conclusion.classification;
    cls.textContent = r.conclusion.classification;
    const conf = document.createElement("span");
    conf.className = "report-conf";
    conf.textContent = `confidence: ${r.conclusion.confidence}`;
    h.append(cls, conf);
    holder.appendChild(h);

    const s = document.createElement("div");
    s.className = "ask-answer";
    s.textContent = r.conclusion.summary;
    holder.appendChild(s);

    const scope = document.createElement("div");
    scope.className = "ask-fresh";
    scope.textContent = `window: ${awst(r.scope.fromUTC)} to ${awst(r.scope.toUTC)} AWST - entities: ${r.scope.entities.join(", ")}`;
    holder.appendChild(scope);

    for (const f of r.observations || []) {
      const row = document.createElement("div");
      row.className = "finding";
      const st = document.createElement("span");
      st.className = "state-badge " + (f.classification === "supported" ? "on" : "off");
      st.textContent = f.classification;
      const txt = document.createElement("span");
      txt.textContent = f.statement;
      row.append(st, txt);
      holder.appendChild(row);
    }

    const cov = document.createElement("div");
    cov.className = "ask-notes";
    for (const c of r.coverage || []) {
      const li = document.createElement("div");
      li.textContent = `coverage ${c.table}: ${c.windowRows} rows in window${c.gaps?.length ? " - gaps: " + c.gaps.join("; ") : " - no gaps"}`;
      cov.appendChild(li);
    }
    holder.appendChild(cov);

    for (const u of r.uncertainty || []) {
      const li = document.createElement("div");
      li.className = "ask-note";
      li.textContent = "uncertainty: " + u;
      holder.appendChild(li);
    }
    for (const n of r.nextSteps || []) {
      const li = document.createElement("div");
      li.className = "ask-note";
      li.textContent = "next: " + n;
      holder.appendChild(li);
    }

    // Evidence links: fetch rows on demand via the evidence route.
    const evidenceIds = r.provenance?.queryIds || [];
    if (evidenceIds.length) {
      const holder2 = document.createElement("div");
      holder2.className = "evidence";
      for (const eid of evidenceIds) {
        const block = document.createElement("div");
        block.className = "evidence-block";
        const head = document.createElement("button");
        head.className = "evidence-head";
        head.textContent = `evidence: ${eid.slice(0, 30)}...`;
        head.addEventListener("click", () => {
          const body = block.querySelector(".evidence-body");
          body.classList.toggle("hidden");
          if (!body.classList.contains("hidden") && !body.dataset.loaded) loadRows(eid, body);
        });
        block.appendChild(head);
        const body = document.createElement("div");
        body.className = "evidence-body hidden";
        block.appendChild(body);
        holder2.appendChild(block);
      }
      holder.appendChild(holder2);
    }

    const ack = document.createElement("button");
    ack.className = "btn small";
    ack.textContent = "mark read";
    ack.addEventListener("click", async () => {
      await post(`/api/investigations/${id}/ack`, {});
      await refreshInbox();
      holder.classList.add("hidden");
      $("inbox-list").classList.remove("hidden");
    });
    holder.appendChild(ack);
  }

  // ------------------------------------------------------------------
  // wiring
  // ------------------------------------------------------------------

  function wire() {
    $("ask-submit").addEventListener("click", () => ask($("ask-input").value.trim()));
    $("ask-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") ask($("ask-input").value.trim());
    });
    // W8: the Investigations tab loads its inbox on activation.
    document.addEventListener("flowviz:tab", (ev) => {
      if (ev.detail && ev.detail.name === "investigations") refreshInbox();
    });
    if (document.body.dataset.tab === "investigations") refreshInbox();
    loadCatalog();
    renderSession();
  }

  return { wire };
})();

document.addEventListener("DOMContentLoaded", () => FlowvizAsk.wire());
