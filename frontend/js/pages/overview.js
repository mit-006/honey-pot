import { get, qs } from "../api.js";
import { SEV_COLORS, areaChart, donut, spark } from "../charts.js";
import {
  dayLabel,
  esc,
  hm,
  kfmt,
  longDate,
  num,
  seg,
  sevBadge,
  timeCell,
  weekdayHour,
} from "../ui.js";

const state = { range: "AUTO" };
const RANGE_TXT = {
  "24h": "last 24 hours",
  "7d": "last 7 days",
  "30d": "last 30 days",
};
const PER = { "24h": "per hour", "7d": "per 6 hours", "30d": "per day" };
const GREEN = "#4DD4AC",
  RED = "#FF8FA0",
  MUTED = "#8B96A8";

const arrow = (v) => (v >= 0 ? "▲" : "▼");
function deltaPct(v, { upGood }) {
  if (v === null || v === undefined)
    return { cls: "mu", txt: "no prior data", color: MUTED };
  const good = upGood === null ? v >= 0 : upGood ? v >= 0 : v < 0;
  const neutralDown = upGood === null && v < 0;
  return {
    cls: neutralDown ? "mu" : good ? "up" : "dn",
    txt: `${arrow(v)} ${Math.abs(v).toFixed(1)}%`,
    color: neutralDown ? MUTED : good ? GREEN : RED,
  };
}

function card(title, value, d, sparkValues) {
  return `<section class="c"><h3><span>${title}</span><span style="text-transform:none;letter-spacing:0;font-weight:500"></span></h3><div class="kr"><div><div class="k">${value}</div><div class="d ${d.cls}">${d.txt}</div></div>${spark(sparkValues, d.color)}</div></section>`;
}

function tick(range, ts) {
  if (range === "24h")
    return `${String(new Date(ts).getHours()).padStart(2, "0")}:00`;
  return dayLabel(ts);
}
function peakText(range, d) {
  const start = d.trend.peakTs - d.bucketMs / 2;
  const when =
    range === "24h"
      ? hm(start)
      : range === "7d"
        ? weekdayHour(start)
        : dayLabel(start);
  return `Peak ${when} · ${Math.round(d.trend.peakPerMin)} evt/min`;
}

function view(d) {
  const k = d.kpis;
  const open = k.openAlerts.change;
  const openD = {
    cls: open === 0 ? "mu" : open < 0 ? "up" : "dn",
    color: open === 0 ? MUTED : open < 0 ? GREEN : RED,
    txt:
      open === 0
        ? "no change"
        : `${arrow(open > 0 ? 1 : -1)} ${Math.abs(open)} vs ${d.range} ago`,
  };
  const decD = k.decoys.attention
    ? { cls: "dn", color: RED, txt: `${k.decoys.attention} need attention` }
    : { cls: "up", color: GREEN, txt: "all healthy" };
  const sevOrder = ["critical", "high", "medium", "low", "info"];
  const sevTotal = sevOrder.reduce((s, x) => s + (d.severity[x] || 0), 0);
  const sevRows = sevOrder.filter(
    (s) => (d.severity[s] || 0) > 0 || s !== "info",
  );
  const pct = (n) => {
    const p = (n / (sevTotal || 1)) * 100;
    return p > 0 && p < 1 ? "<1%" : `${Math.round(p)}%`;
  };
  const labels = Array.from({ length: 5 }, (_, i) =>
    i === 4 ? "now" : tick(d.range, d.from + (i / 4) * (d.now - d.from)),
  );
  const maxC = Math.max(1, ...d.countries.map((c) => c.count));
  return `
<div class="h"><div><h1>Overview</h1><div class="sub">${longDate(d.now)} · ${RANGE_TXT[d.range]}</div></div><div class="row">${seg(
    [
      ["24h", "24h"],
      ["7d", "7d"],
      ["30d", "30d"],
    ],
    d.range,
  )}<button class="btn p" type="button" data-print>Export report</button></div></div>
<div class="g" style="grid-template-columns:repeat(auto-fit,minmax(min(100%,200px),1fr))">
${card("Events", num(k.events.value), deltaPct(k.events.delta, { upGood: true }), k.events.spark)}
${card("Unique attackers", num(k.attackers.value), deltaPct(k.attackers.delta, { upGood: true }), k.attackers.spark)}
${card("Open alerts", num(k.openAlerts.value), openD, k.openAlerts.spark)}
${card("Critical events", num(k.critical.value), deltaPct(k.critical.delta, { upGood: false }), k.critical.spark)}
${card("Decoys online", `${k.decoys.online} / ${k.decoys.total}`, decD, k.decoys.spark)}
</div>
<div class="w"><section class="c"><h3><span>Threat activity · events ${PER[d.range]}</span><span style="text-transform:none;letter-spacing:0;font-weight:500">${peakText(d.range, d)}</span></h3>
${areaChart(d.trend.values, { id: "a1", label: "Events over time" })}
<div class="row mu m" style="justify-content:space-between;font-size:11px">${labels.map((l) => `<span>${l}</span>`).join("")}</div></section>
<section class="c"><h3><span>Severity distribution</span><span style="text-transform:none;letter-spacing:0;font-weight:500"></span></h3>
<div class="row" style="flex-wrap:nowrap;gap:18px;justify-content:center">${donut(
    sevOrder.map((s) => ({ value: d.severity[s] || 0, color: SEV_COLORS[s] })),
    "Severity distribution",
  )}
<div style="flex:1">${sevRows.map((s) => `<div class="hr"><span><i class="dot" style="background:${SEV_COLORS[s]}"></i>${s[0].toUpperCase() + s.slice(1)}</span><span class="m">${pct(d.severity[s] || 0)}</span></div>`).join("")}</div></div></section></div>
<div class="w"><section class="c"><h3><span>Recent events</span><span style="text-transform:none;letter-spacing:0;font-weight:500"><a href="#/events" style="color:#22D3EE">View all</a></span></h3>
<div class="sc"><table class="t"><thead><tr><th>Time</th><th>Severity</th><th>Decoy</th><th>Source</th><th>Activity</th></tr></thead><tbody>
${d.recent.length ? d.recent.map((e) => `<tr data-id="${e.id}"><td><span class="m">${timeCell(e.ts)}</span></td><td>${sevBadge(e.severity)}</td><td>${esc(e.decoy)}</td><td><span class="m">${esc(e.src_ip)}</span></td><td>${esc(e.summary)}</td></tr>`).join("") : '<tr class="empty-row"><td colspan="5">No events yet.</td></tr>'}
</tbody></table></div></section>
<div class="col"><section class="c"><h3><span>System health</span><span style="text-transform:none;letter-spacing:0;font-weight:500"></span></h3>
${d.health.map((h) => `<div class="hr"><span><i class="dot" style="background:${h.state === "ok" ? "#4DD4AC" : "#FFD43B"}"></i>${h.name}</span><span class="m">${h.text}</span></div>`).join("")}</section>
<section class="c"><h3><span>Top source countries</span><span style="text-transform:none;letter-spacing:0;font-weight:500"></span></h3>
${d.countries.length ? d.countries.map((c) => `<div class="hb"><span title="${esc(c.name)}">${esc(c.name)}</span><div><b style="width:${Math.round((88 * c.count) / maxC)}%"></b></div><span class="m">${kfmt(c.count)}</span></div>`).join("") : '<div class="mu">No data in range.</div>'}</section></div></div>`;
}

export async function mount(ctx) {
  const { root } = ctx;
  if (state.range === "AUTO") state.range = "24h";
  async function load() {
    const d = await get("/overview" + qs({ range: state.range }));
    root.innerHTML = view(d);
  }
  root.addEventListener("click", (e) => {
    const s = e.target.closest("[data-seg]");
    if (s) {
      state.range = s.dataset.seg;
      load();
      return;
    }
    if (e.target.closest("[data-print]")) {
      window.print();
      return;
    }
    const row = e.target.closest("tr[data-id]");
    if (row) ctx.go(`#/events?sel=${row.dataset.id}`);
  });
  await load();
  return { live: () => load().catch(() => {}) };
}
