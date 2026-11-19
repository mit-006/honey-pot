import { get, qs } from '../api.js';
import { PROTO_COLORS, areaChart, donut, heatmap, spark } from '../charts.js';
import {  dur, kfmt, num, seg } from '../ui.js';

const S = { range: '24h' };
const GREEN = '#4DD4AC', RED = '#FF8FA0', MUTED = '#8B96A8';
const RANGE_TXT = { '24h': 'Last 24 hours', '7d': 'Last 7 days', '30d': 'Last 30 days' };
const arrow = (v) => (v >= 0 ? '▲' : '▼');

function card(title, value, d, sp) {
  return `<section class="c"><h3><span>${title}</span><span style="text-transform:none;letter-spacing:0;font-weight:500"></span></h3><div class="kr"><div><div class="k">${value}</div><div class="d ${d.cls}">${d.txt}</div></div>${sp ? spark(sp, d.color) : ''}</div></section>`;
}
const pctD = (v) => (v === null || v === undefined ? { cls: 'mu', color: MUTED, txt: 'no prior data' } : { cls: v >= 0 ? 'up' : 'mu', color: v >= 0 ? GREEN : MUTED, txt: `${arrow(v)} ${Math.abs(v).toFixed(1)}%` });

function view(d) {
  const k = d.kpis;
  const mt = k.mtta.deltaMs === null ? { cls: 'mu', color: MUTED, txt: 'no prior data' } : { cls: k.mtta.deltaMs <= 0 ? 'up' : 'dn', color: k.mtta.deltaMs <= 0 ? GREEN : RED, txt: `${arrow(k.mtta.deltaMs)} ${dur(Math.abs(k.mtta.deltaMs))}` };
  const det = k.detection.deltaPts === null ? { cls: 'mu', color: MUTED, txt: 'no prior data' } : { cls: k.detection.deltaPts >= 0 ? 'up' : 'dn', color: k.detection.deltaPts >= 0 ? GREEN : RED, txt: `${arrow(k.detection.deltaPts)} ${Math.abs(k.detection.deltaPts).toFixed(1)}%` };
  const ptotal = d.protocols.reduce((s, p) => s + p.count, 0) || 1;
  const maxT = Math.max(1, ...d.types.map((t) => t.count));
  return `
<div class="h"><div><h1>Analytics</h1><div class="sub">Trends and breakdowns</div></div><div class="row">${seg([['24h', '24h'], ['7d', '7d'], ['30d', '30d']], d.range)}<button class="btn" type="button" data-print>Export PDF</button></div></div>
<div class="g">
${card(`Events (${d.range})`, num(k.events.value), pctD(k.events.delta), k.events.spark)}
${card('Unique attackers', num(k.attackers.value), pctD(k.attackers.delta), k.attackers.spark)}
${card('Mean time to ack', dur(k.mtta.valueMs), mt, null)}
${card('Detection rate', k.detection.value === null ? '—' : `${k.detection.value.toFixed(1)}%`, det, null)}
</div>
<div class="w"><section class="c"><h3><span>Threat trend · events vs unique attackers</span><span style="text-transform:none;letter-spacing:0;font-weight:500">${RANGE_TXT[d.range]}</span></h3>
${areaChart(d.trend.events, { id: 'a2', h: 200, label: 'Events and unique attackers over time', second: d.trend.attackers })}
<div class="row mu" style="font-size:12px"><span><i class="dot" style="background:#22D3EE"></i>Events</span><span><i class="dot" style="background:#FFA94D"></i>Unique attackers</span></div></section>
<section class="c"><h3><span>By protocol</span><span style="text-transform:none;letter-spacing:0;font-weight:500"></span></h3>
<div class="row" style="flex-wrap:nowrap;gap:18px;justify-content:center">${donut(d.protocols.map((p, i) => ({ value: p.count, color: PROTO_COLORS[i] })), 'Events by protocol')}
<div style="flex:1">${d.protocols.length ? d.protocols.map((p, i) => `<div class="hr"><span><i class="dot" style="background:${PROTO_COLORS[i]}"></i>${p.name}</span><span class="m">${Math.round((p.count / ptotal) * 100)}%</span></div>`).join('') : '<div class="mu">No data in range.</div>'}</div></div></section></div>
<div class="g" style="grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr))">
<section class="c"><h3><span>Top attack types</span><span style="text-transform:none;letter-spacing:0;font-weight:500"></span></h3>${d.types.length ? d.types.map((t) => `<div class="hb"><span>${t.name}</span><div><b style="width:${Math.round((92 * t.count) / maxT)}%"></b></div><span class="m">${kfmt(t.count)}</span></div>`).join('') : '<div class="mu">No data in range.</div>'}</section>
<section class="c"><h3><span>Activity by hour and weekday</span><span style="text-transform:none;letter-spacing:0;font-weight:500">Last 30 days · local time</span></h3>${heatmap(d.heatmap)}</section></div>`;
}

export async function mount(ctx) {
  const { root } = ctx;
  const tz = -new Date().getTimezoneOffset();
  const load = async () => { root.innerHTML = view(await get('/analytics' + qs({ range: S.range, tz }))); };
  root.addEventListener('click', (e) => {
    const s = e.target.closest('[data-seg]'); if (s) { S.range = s.dataset.seg; load(); return; }
    if (e.target.closest('[data-print]')) window.print();
  });
  await load();
  return { live: () => load().catch(() => {}) };
}
