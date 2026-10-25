/* Chart wrappers (plan 6.1): one fixed renderer per chart type, driven by a
 * server-validated ChartSpec and chartData computed from query results.
 * Spec references only real result columns; nothing here executes
 * model-generated code or expressions. ECharts is vendored; no build step. */
window.FlowvizCharts = (() => {
  "use strict";

  const C = {
    text: "#8b93a7",
    label: "#c6ccd9",
    grid: "#232936",
    orange: "#f6821f",
    blue: "#4aa3ff",
    green: "#2fd48f",
    purple: "#a78bfa",
    red: "#ff6b6b",
  };
  const SERIES = [C.orange, C.blue, C.green, C.purple, C.red];

  const instances = new WeakMap();

  function mount(el) {
    if (!window.echarts) return null;
    let ch = instances.get(el);
    if (!ch) {
      ch = echarts.init(el, null, { renderer: "canvas" });
      instances.set(el, ch);
    }
    return ch;
  }

  const baseAxis = {
    axisLine: { lineStyle: { color: C.grid } },
    axisLabel: { color: C.text, fontSize: 11 },
    splitLine: { lineStyle: { color: "rgba(35,41,54,0.6)" } },
  };

  function timeFmt(ts) {
    try {
      return new Date(ts).toLocaleString("en-AU", {
        timeZone: "Australia/Perth",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return String(ts);
    }
  }

  function tooltipBase() {
    return {
      trigger: "axis",
      backgroundColor: "#171b25",
      borderColor: C.grid,
      textStyle: { color: C.label, fontSize: 12 },
    };
  }

  // time-series and comparison: [{x, y, series?}]; comparison adds baseline.
  function timeSeries(el, spec, data, baselineData) {
    const ch = mount(el);
    if (!ch) return;
    const series = new Map();
    for (const d of data) {
      const k = d.series || "count";
      if (!series.has(k)) series.set(k, []);
      series.get(k).push([d.x, d.y]);
    }
    const option = {
      backgroundColor: "transparent",
      grid: { left: 56, right: 20, top: 28, bottom: 48 },
      tooltip: {
        ...tooltipBase(),
        formatter: (ps) =>
          ps
            .map(
              (p) =>
                `${timeFmt(p.value[0])}<br/>${p.marker} ${p.seriesName}: <b>${p.value[1]}</b>`,
            )
            .join("<br/>"),
      },
      xAxis: { type: "time", ...baseAxis },
      yAxis: { type: "value", ...baseAxis },
      dataZoom: [
        // W8: plain wheel scrolls the workspace; shift+wheel zooms.
        { type: "inside", zoomOnMouseWheel: "shift" },
        { type: "slider", height: 16, bottom: 8, borderColor: C.grid, textStyle: { color: C.text } },
      ],
      series: [...series.entries()].map(([k, pts], i) => ({
        name: k,
        type: "line",
        showSymbol: false,
        lineStyle: { width: 1.8, color: SERIES[i % SERIES.length] },
        itemStyle: { color: SERIES[i % SERIES.length] },
        areaStyle: { opacity: 0.06 },
        data: pts,
      })),
    };
    if (baselineData && baselineData.length) {
      option.series.push({
        name: "previous period",
        type: "line",
        showSymbol: false,
        lineStyle: { width: 1.4, color: "#5b6272", type: "dashed" },
        itemStyle: { color: "#5b6272" },
        data: baselineData.map((d) => [d.x, d.y]),
      });
    }
    ch.setOption(option, true);
    el.__echarts__ = ch;
    return ch;
  }

  // ranked-bars: [{name, value}]
  function rankedBars(el, spec, data) {
    const ch = mount(el);
    if (!ch) return;
    const rows = data.slice(0, 15);
    ch.setOption(
      {
        backgroundColor: "transparent",
        grid: { left: 10, right: 48, top: 12, bottom: 10, containLabel: true },
        tooltip: {
          backgroundColor: "#171b25",
          borderColor: C.grid,
          textStyle: { color: C.label, fontSize: 12 },
        },
        xAxis: { type: "value", ...baseAxis, splitLine: { lineStyle: { color: "rgba(35,41,54,0.6)" } } },
        yAxis: {
          type: "category",
          data: rows.map((r) => r.name).reverse(),
          axisLine: { lineStyle: { color: C.grid } },
          axisLabel: { color: C.label, fontSize: 11, width: 160, overflow: "truncate" },
        },
        series: [
          {
            type: "bar",
            data: rows.map((r) => r.value).reverse(),
            itemStyle: { color: C.orange, borderRadius: [0, 3, 3, 0] },
            barMaxWidth: 16,
            label: { show: true, position: "right", color: C.text, fontSize: 11 },
          },
        ],
      },
      true,
    );
    return ch;
  }

  // coverage-grid: [{t, hour, c}] -> heatmap table x hour
  function coverageGrid(el, spec, data) {
    const ch = mount(el);
    if (!ch) return;
    const tables = [...new Set(data.map((d) => d.t))];
    const hours = [...new Set(data.map((d) => String(d.hour)))].sort();
    const cell = new Map(data.map((d) => [`${d.t}|${d.hour}`, d.c]));
    ch.setOption(
      {
        backgroundColor: "transparent",
        grid: { left: 10, right: 20, top: 12, bottom: 44, containLabel: true },
        tooltip: {
          backgroundColor: "#171b25",
          borderColor: C.grid,
          textStyle: { color: C.label, fontSize: 12 },
          formatter: (p) => `${p.value[1]} at ${timeFmt(hours[p.value[0]])}: <b>${p.value[2]}</b> rows`,
        },
        xAxis: {
          type: "category",
          data: hours,
          axisLine: { lineStyle: { color: C.grid } },
          axisLabel: { color: C.text, fontSize: 10, formatter: (v) => timeFmt(v).slice(0, 5) },
        },
        yAxis: {
          type: "category",
          data: tables,
          axisLine: { lineStyle: { color: C.grid } },
          axisLabel: { color: C.label, fontSize: 11 },
        },
        visualMap: {
          min: 0,
          max: Math.max(1, ...data.map((d) => d.c)),
          calculable: false,
          show: false,
          inRange: { color: ["#171b25", "#3a2f1a", "#b35f14", C.orange] },
        },
        series: [
          {
            type: "heatmap",
            data: tables.flatMap((t, y) =>
              hours.map((h, x) => [x, y, cell.get(`${t}|${h}`) ?? 0]),
            ),
            itemStyle: { borderColor: "#0b0d12", borderWidth: 1 },
          },
        ],
      },
      true,
    );
    return ch;
  }

  function resizeAll() {
    for (const el of document.querySelectorAll(".chart-box")) {
      const ch = instances.get(el);
      if (ch) ch.resize();
    }
  }
  window.addEventListener("resize", resizeAll);

  return { timeSeries, rankedBars, coverageGrid, resizeAll };
})();
