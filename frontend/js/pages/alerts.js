import { get, post, qs } from '../api.js';
import { $, $$, age, debounce, esc, filterMenu, hm, initials, num, pager, sevBadge, statusBadge, syncMenu, toast, togglePop } from '../ui.js';

const SEVS = [['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info']];
const S = { status: 'open', sev: new Set(), q: '', page: 1, checked: new Set() };

export async function mount(ctx) {
  const { root, can } = ctx;
  let data = { rows: [], total: 0, page: 1, pages: 1, pageSize: 8, counts: { open: 0, acknowledged: 0, resolved30: 0 } };
  const urlQ = ctx.params.get('q');
  if (urlQ !== null) { S.q = urlQ; S.status = 'all'; }

  const fetchData = async () => { data = await get('/alerts' + qs({ status: S.status, severity: S.sev, q: S.q, page: S.page, pageSize: 8 })); S.page = data.page; };

  function skeleton() {
    root.innerHTML = `
<div class="h"><div><h1>Alerts</h1><div class="sub" id="sub"></div></div><div class="row"></div></div>
<div class="c bar"><div class="row"><div id="tabs"></div>${filterMenu('sev', 'Severity', SEVS, S.sev)}<span id="bulk" class="row"></span></div>
<input class="in" id="q" style="width:260px;max-width:100%" placeholder="Search alerts" aria-label="Search alerts" value="${esc(S.q)}"></div>
<section class="c"><h3><span>Alert queue</span><span style="text-transform:none;letter-spacing:0;font-weight:500"></span></h3><div class="sc" id="tbl"></div><div id="pgr"></div></section>`;
  }

  function actions(a) {
    if (a.status === 'resolved') return `<span class="mu">Closed ${hm(a.resolved_at)}</span>`;
    const dis = can.analyst ? '' : 'disabled title="Requires analyst role"';
    return `<div class="row" style="flex-wrap:nowrap;justify-content:flex-end">${a.status === 'open' ? `<button class="btn sm" type="button" data-one="acknowledge" data-aid="${a.id}" ${dis}>Acknowledge</button>` : ''}<button class="btn sm p" type="button" data-one="resolve" data-aid="${a.id}" ${dis}>Resolve</button></div>`;
  }

  function render() {
    const c = data.counts;
    $(root, '#sub').textContent = `${num(c.open)} open · ${num(c.acknowledged)} acknowledged · ${num(c.resolved30)} resolved this month`;
    $(root, '#tabs').innerHTML = `<div class="seg">${[['open', `Open ${num(c.open)}`], ['acknowledged', `Acknowledged ${num(c.acknowledged)}`], ['resolved', `Resolved ${num(c.resolved30)}`], ['all', 'All']]
      .map(([v, l]) => `<button type="button" data-seg="${v}" class="${v === S.status ? 'on' : ''}">${l}</button>`).join('')}</div>`;
    const ids = new Set(data.rows.map((r) => r.id));
    for (const id of [...S.checked]) if (!ids.has(id)) S.checked.delete(id);
    const n = S.checked.size;
    $(root, '#bulk').innerHTML = n && can.analyst ? `<button class="btn sm" type="button" data-bulk="acknowledge">Acknowledge (${n})</button><button class="btn sm p" type="button" data-bulk="resolve">Resolve (${n})</button>` : '';
    const allOn = data.rows.length && data.rows.every((r) => S.checked.has(r.id));
    $(root, '#tbl').innerHTML = `<table class="t"><thead><tr><th><input type="checkbox" data-all aria-label="Select all rows" ${allOn ? 'checked' : ''}></th><th>Alert</th><th>Severity</th><th>Status</th><th>Owner</th><th>Age</th><th style="text-align:right">Actions</th></tr></thead><tbody>
${data.rows.length ? data.rows.map((a) => `<tr><td><input type="checkbox" data-chk="${a.id}" aria-label="Select row" ${S.checked.has(a.id) ? 'checked' : ''}></td>
<td>${a.event_id ? `<a href="#/events?sel=${a.event_id}" style="text-decoration:none" title="${esc(a.ref)} · source ${esc(a.src_ip)}"><b>${esc(a.title)}</b></a>` : `<b>${esc(a.title)}</b>`} <span class="mu m">${esc(a.code)}</span></td>
<td>${sevBadge(a.severity)}</td><td>${statusBadge(a.status)}</td><td title="${esc(a.owner_name || 'Unassigned')}">${a.owner_name ? esc(initials(a.owner_name)) : '—'}</td><td>${age(a.created_at)}</td><td>${actions(a)}</td></tr>`).join('') : `<tr class="empty-row"><td colspan="7">${S.q || S.sev.size ? 'No alerts match these filters.' : 'Nothing here. The queue is clear.'}</td></tr>`}
</tbody></table>`;
    $(root, '#pgr').innerHTML = data.total ? pager(data.page, data.pages, data.total, data.pageSize) : '';
  }

  async function reload() { await fetchData(); render(); ctx.refreshBadge(); }

  async function run(fn, okMsg) {
    try { const r = await fn(); toast(typeof okMsg === 'function' ? okMsg(r) : okMsg); await reload(); } catch (ex) { toast(ex.message, 'err'); await reload(); }
  }

  await fetchData(); skeleton(); render();

  const search = debounce(() => { S.q = $(root, '#q').value.trim(); S.page = 1; S.checked.clear(); reload(); }, 300);
  root.addEventListener('input', (e) => { if (e.target.id === 'q') search(); });
  root.addEventListener('change', (e) => {
    const t = e.target;
    if (t.dataset.fopt) { t.checked ? S.sev.add(t.value) : S.sev.delete(t.value); syncMenu(root, 'sev', S.sev); S.page = 1; reload(); return; }
    if (t.matches('[data-all]')) { data.rows.forEach((r) => (t.checked ? S.checked.add(r.id) : S.checked.delete(r.id))); render(); return; }
    if (t.dataset.chk) { const id = Number(t.dataset.chk); t.checked ? S.checked.add(id) : S.checked.delete(id); render(); }
  });
  root.addEventListener('click', (e) => {
    const t = e.target;
    const pop = t.closest('[data-pop]'); if (pop) { togglePop(pop); return; }
    const clr = t.closest('[data-fclear]'); if (clr) { S.sev.clear(); syncMenu(root, 'sev', S.sev); S.page = 1; reload(); return; }
    const sg = t.closest('[data-seg]'); if (sg) { S.status = sg.dataset.seg; S.page = 1; S.checked.clear(); reload(); return; }
    const pg = t.closest('[data-pg]'); if (pg && !pg.disabled) { S.page = Number(pg.dataset.pg); reload(); return; }
    const one = t.closest('[data-one]');
    if (one) { run(() => post(`/alerts/${one.dataset.aid}/${one.dataset.one}`), one.dataset.one === 'resolve' ? 'Alert resolved' : 'Alert acknowledged'); return; }
    const bulk = t.closest('[data-bulk]');
    if (bulk) { const ids = [...S.checked]; S.checked.clear(); run(() => post('/alerts/bulk', { ids, action: bulk.dataset.bulk }), (r) => `${r.done} alert${r.done === 1 ? '' : 's'} updated${r.skipped ? `, ${r.skipped} skipped` : ''}`); }
  });

  return { live: async () => { await fetchData(); render(); } };
}
