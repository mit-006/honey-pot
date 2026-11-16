// SVG builders that emit the same markup/geometry as the approved design.
const f1 = (n) => (Math.round(n * 10) / 10).toString();

export function spark(values, color = '#4DD4AC', w = 80, h = 28) {
  const n = values.length;
  if (n < 2) return '';
  const min = Math.min(...values), max = Math.max(...values), span = max - min || 1;
  const pts = values.map((v, i) => `${f1((i * w) / (n - 1))},${f1(max === min ? h / 2 : 2 + (1 - (v - min) / span) * (h - 4))}`).join(' ');
  return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" aria-hidden="true"><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5"/></svg>`;
}

const line = (values, w, h, max) => values.map((v, i) => `${f1((i * w) / Math.max(1, values.length - 1))},${f1(12 + (1 - v / (max * 1.05 || 1)) * (h - 32))}`);

export function areaChart(values, { id = 'a1', w = 600, h = 190, label = 'Trend chart', second = null } = {}) {
  const max = Math.max(1, ...values);
  const pts = line(values, w, h, max);
  const grid = [0.25, 0.5, 0.75].map((p) => `<line x1="0" x2="${w}" y1="${Math.round(h * p)}" y2="${Math.round(h * p)}" stroke="#1F2937"/>`).join('');
  let extra = '';
  if (second) {
    const p2 = line(second, w, h, Math.max(1, ...second));
    extra = `<polyline points="${p2.join(' ')}" fill="none" stroke="#FFA94D" stroke-width="2" stroke-dasharray="5 4" vector-effect="non-scaling-stroke"/>`;
  }
  return `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" preserveAspectRatio="none" role="img" aria-label="${label}">
<defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#22D3EE" stop-opacity=".3"/><stop offset="1" stop-color="#22D3EE" stop-opacity="0"/></linearGradient></defs>${grid}
<polygon points="0,${h} ${pts.join(' ')} ${w},${h}" fill="url(#${id})"/>
<polyline points="${pts.join(' ')}" fill="none" stroke="#22D3EE" stroke-width="2" vector-effect="non-scaling-stroke"/>${extra}</svg>`;
}

/** items: [{value, color}] (values are shares, any scale). */
export function donut(items, label) {
  const total = items.reduce((s, i) => s + i.value, 0) || 1;
  let cum = 0;
  const circles = items.filter((i) => i.value > 0).map((i) => {
    const pct = (i.value / total) * 100;
    const c = `<circle cx="21" cy="21" r="15.9155" fill="none" stroke="${i.color}" stroke-width="5" stroke-dasharray="${f1(Math.max(0.3, pct - 0.6))} ${f1(100 - Math.max(0.3, pct - 0.6))}" stroke-dashoffset="${f1(25 - cum)}"/>`;
    cum += pct;
    return c;
  }).join('');
  const empty = total === 1 && !items.some((i) => i.value > 0) ? '<circle cx="21" cy="21" r="15.9155" fill="none" stroke="#182030" stroke-width="5"/>' : '';
  return `<svg viewBox="0 0 42 42" width="130" height="130" role="img" aria-label="${label}">${empty}${circles}</svg>`;
}

export function decoyBars(values, color) {
  const max = Math.max(1, ...values);
  const rects = values.map((v, i) => {
    const h = v === 0 ? 2 : Math.max(3, Math.round((v / max) * 34));
    return `<rect x="${f1(0.6 + i * 4.1667)}" y="${34 - h}" width="2.9" height="${h}" fill="${color}"${v === 0 ? ' opacity=".35"' : ''}/>`;
  }).join('');
  return `<svg viewBox="0 0 100 34" width="100%" height="34" preserveAspectRatio="none" aria-hidden="true">${rects}</svg>`;
}

const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
export function heatmap(matrix) {
  const max = Math.max(1, ...matrix.flat());
  let out = '';
  matrix.forEach((row, r) => row.forEach((v, c) => {
    const o = (0.08 + 0.92 * Math.pow(v / max, 0.85)).toFixed(2);
    out += `<rect x="${c * 10}" y="${r * 10}" width="9" height="9" rx="1.5" fill="#22D3EE" opacity="${o}"><title>${DAYS[r]} ${String(c).padStart(2, '0')}:00 · ${v.toLocaleString('en-US')} events</title></rect>`;
  }));
  return `<svg viewBox="0 0 240 70" width="100%" height="180" preserveAspectRatio="none" role="img" aria-label="Activity by hour and weekday">${out}</svg>`;
}

export const SEV_COLORS = { critical: '#FF6B81', high: '#FFA94D', medium: '#FFD43B', low: '#4DD4AC', info: '#7CC4FF' };
export const PROTO_COLORS = ['#22D3EE', '#7CC4FF', '#FFA94D', '#FFD43B', '#4DD4AC'];
