import { del, get, patch, post } from '../api.js';
import { decoyBars } from '../charts.js';
import { $, confirmBox, dayLabel, esc, field, hm, isToday, modal, num, options, seg, timeCell, toast, toggle } from '../ui.js';

const PROTOS = ['SSH', 'HTTP', 'MySQL', 'SMB', 'Redis', 'RDP', 'FTP', 'DNS'];
const DEFAULT_PORTS = { SSH: 22, HTTP: 8080, MySQL: 3306, SMB: 445, Redis: 6379, RDP: 3389, FTP: 21, DNS: 53 };
const COLOR = { online: '#4DD4AC', degraded: '#FFD43B', paused: '#8B96A8' };
const LABEL = { online: 'Online', degraded: 'Degraded', paused: 'Paused' };
const S = { status: 'all' };

function lastHit(ts, now) {
  if (!ts) return 'Never';
  if (isToday(ts)) return hm(ts);
  return now - ts < 2 * 86400e3 && new Date(ts).getDate() === new Date(now - 86400e3).getDate() ? 'Yesterday' : dayLabel(ts);
}

export async function mount(ctx) {
  const { root, can } = ctx;
  let data;
  const load = async () => { data = await get(`/decoys?status=${S.status}`); render(); };

  function card(d) {
    const dis = can.admin ? '' : 'disabled';
    return `<section class="c"><div class="kr"><div><b style="font-size:14px">${esc(d.name)}</b><div class="mu m">${esc(d.protocol)} · ${esc(d.host)}:${d.port}</div></div><span><i class="dot" style="background:${COLOR[d.status]}"></i>${LABEL[d.status]}</span></div>
<div class="st"><div class="mu">Events 24h<b>${num(d.events24)}</b></div><div class="mu">Attackers<b>${num(d.attackers24)}</b></div><div class="mu">Last hit<b>${lastHit(d.lastHit, data.now)}</b></div></div>
${decoyBars(d.bars, COLOR[d.status])}
<div class="ft"><span>${toggle(d.enabled, { label: `${d.enabled ? 'Disable' : 'Enable'} ${d.name}`, attrs: `data-toggle="${d.id}"`, disabled: !can.admin, title: can.admin ? '' : 'Requires admin role' })} <span class="mu">Enabled</span></span>
<button class="btn sm" type="button" data-cfg="${d.id}" ${dis} ${can.admin ? '' : 'title="Requires admin role"'}>Configure</button></div></section>`;
  }

  function render() {
    const c = data.counts;
    root.innerHTML = `
<div class="h"><div><h1>Decoy Management</h1><div class="sub">${data.total} decoys · ${data.segments} network segments</div></div><div class="row">${seg([['all', 'All'], ['online', `Online`], ['degraded', 'Degraded'], ['paused', 'Paused']], S.status)}<button class="btn p" type="button" data-deploy ${can.admin ? '' : 'disabled title="Requires admin role"'}>+ Deploy decoy</button></div></div>
<div class="g" style="grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr))">${data.decoys.length ? data.decoys.map(card).join('') : `<div class="c ph" style="grid-column:1/-1">No ${S.status} decoys.</div>`}</div>
<section class="c"><h3><span>Recent decoy interactions</span><span style="text-transform:none;letter-spacing:0;font-weight:500"><a href="#/events" style="color:#22D3EE">View all</a></span></h3><div class="sc"><table class="t"><thead><tr><th>Time</th><th>Decoy</th><th>Source</th><th>Action</th></tr></thead><tbody>
${data.recent.length ? data.recent.map((e) => `<tr data-id="${e.id}"><td><span class="m">${timeCell(e.ts)}</span></td><td>${esc(e.decoy)}</td><td><span class="m">${esc(e.src_ip)}</span></td><td>${esc(e.summary)}</td></tr>`).join('') : '<tr class="empty-row"><td colspan="4">No interactions yet.</td></tr>'}</tbody></table></div></section>`;
    // counts in the filter tooltips (kept out of labels to match the design)
    root.querySelectorAll('[data-seg]').forEach((b) => { const n = c[b.dataset.seg]; if (n !== undefined) b.title = `${n} decoys`; });
  }

  const form = (d = {}, segments = []) => `
${field('Name', `<input class="in" name="name" value="${esc(d.name || '')}" placeholder="ssh-dmz-03" pattern="[a-z0-9][a-z0-9-]*" maxlength="40" required>`, 'Lowercase letters, digits and dashes')}
<div class="g2">${field('Protocol', `<select class="in" name="protocol" ${d.id ? 'disabled' : ''}>${options(PROTOS.map((p) => [p, p]), d.protocol || 'SSH')}</select>`)}
${field('Port', `<input class="in" name="port" type="number" min="1" max="65535" value="${d.port || ''}" placeholder="default for protocol">`)}</div>
<div class="g2">${field('Host / IP', `<input class="in" name="host" value="${esc(d.host || '')}" placeholder="10.20.1.40" required>`)}
${field('Segment', `<input class="in" name="segment" list="segs" value="${esc(d.segment || 'DMZ')}" required><datalist id="segs">${segments.map((s) => `<option value="${esc(s)}">`).join('')}</datalist>`)}</div>
${d.id ? field('Health', `<select class="in" name="health">${options([['online', 'Online'], ['degraded', 'Degraded']], d.health)}</select>`, 'Normally reported by the sensor heartbeat') : ''}
${field('Notes', `<input class="in" name="notes" maxlength="300" value="${esc(d.notes || '')}">`)}`;
  const segs = () => [...new Set(data.decoys.map((d) => d.segment))];
  const body = (fd, keys) => Object.fromEntries(keys.map((k) => [k, fd.get(k)]).filter(([, v]) => v !== null));

  async function deploy() {
    modal({
      title: 'Deploy decoy', submitLabel: 'Deploy decoy',
      html: `${form({}, segs())}<p class="mu" style="margin:0;font-size:12px">This registers a <b>simulated</b> decoy. No network listener is started and nothing is exposed.</p>`,
      onSubmit: async (fd, close) => { await post('/decoys', { ...body(fd, ['name', 'protocol', 'host', 'segment', 'notes']), port: fd.get('port') || undefined }); close(); toast('Decoy deployed'); await load(); },
    });
  }

  function configure(d) {
    modal({
      title: `Configure ${d.name}`, submitLabel: 'Save changes',
      html: `${form(d, segs())}<div class="ft" style="border:0;margin:0;padding:0"><button type="button" class="btn danger sm" data-del>Delete decoy…</button></div>`,
      onMount: (f, close) => {
        f.querySelector('[data-del]').addEventListener('click', async () => {
          if (await confirmBox({ title: 'Delete decoy', text: `Delete ${d.name} and all of its recorded events? This cannot be undone.`, confirmLabel: 'Delete', danger: true })) {
            try { await del(`/decoys/${d.id}`); close(); toast('Decoy deleted'); await load(); } catch (ex) { toast(ex.message, 'err'); }
          }
        });
      },
      onSubmit: async (fd, close) => { await patch(`/decoys/${d.id}`, { ...body(fd, ['name', 'host', 'segment', 'notes', 'health']), port: fd.get('port') }); close(); toast('Decoy updated'); await load(); },
    });
  }

  await load();
  root.addEventListener('click', async (e) => {
    const t = e.target;
    const sg = t.closest('[data-seg]'); if (sg) { S.status = sg.dataset.seg; await load(); return; }
    if (t.closest('[data-deploy]')) { deploy(); return; }
    const cfg = t.closest('[data-cfg]'); if (cfg) { configure(data.decoys.find((d) => d.id === Number(cfg.dataset.cfg))); return; }
    const tg = t.closest('[data-toggle]');
    if (tg) {
      const d = data.decoys.find((x) => x.id === Number(tg.dataset.toggle));
      try { await patch(`/decoys/${d.id}`, { enabled: !d.enabled }); toast(`${d.name} ${d.enabled ? 'paused' : 'enabled'}`); await load(); } catch (ex) { toast(ex.message, 'err'); }
      return;
    }
    const row = t.closest('tr[data-id]'); if (row) ctx.go(`#/events?sel=${row.dataset.id}`);
  });
  return { live: () => load().catch(() => {}) };
}
