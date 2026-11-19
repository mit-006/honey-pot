import {  get, patch, post, qs } from '../api.js';
import {  dayLabel, esc, field, hms, modal,  options, pager, roleBadge, seg, toast, toggle } from '../ui.js';

const S = { range: 'today', page: 1 };
const tz = () => -new Date().getTimezoneOffset();
const RETENTION = [30, 60, 90, 180, 365];
const stamp = (ts) => (new Date(ts).toDateString() === new Date().toDateString() ? hms(ts) : `${dayLabel(ts)} ${hms(ts)}`);

function secretBox(label, value) {
  return `<div class="fld"><span>${esc(label)}</span><div class="secret"><code>${esc(value)}</code><button type="button" class="btn sm" data-copy="${esc(value)}">Copy</button></div><small class="mu">Shown once. Store it somewhere safe.</small></div>`;
}

export async function mount(ctx) {
  const { root, can } = ctx;
  let log, users, settings;

  const load = async () => {
    [log, users, settings] = await Promise.all([get('/audit' + qs({ range: S.range, page: S.page, pageSize: 10, tz: tz() })), get('/users'), get('/settings')]);
    S.page = log.page;
  };

  function render() {
    root.innerHTML = `
<div class="h"><div><h1>Audit Logs &amp; Settings</h1><div class="sub">Activity history, users and configuration</div></div><div class="row"><button class="btn" type="button" data-export>Export log</button></div></div>
<div class="w"><section class="c"><h3><span>Audit log</span><span style="text-transform:none;letter-spacing:0;font-weight:500">${seg([['today', 'Today'], ['7d', '7d'], ['30d', '30d']], S.range)}</span></h3>
<div class="sc"><table class="t"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th>IP</th></tr></thead><tbody>
${log.rows.length ? log.rows.map((a) => `<tr><td><span class="m">${stamp(a.ts)}</span></td><td>${esc(a.user)}</td><td>${esc(a.action)}</td><td>${esc(a.target)}</td><td><span class="m">${esc(a.ip || '—')}</span></td></tr>`).join('') : '<tr class="empty-row"><td colspan="5">No activity in this period.</td></tr>'}</tbody></table></div>
${log.total ? pager(log.page, log.pages, log.total, log.pageSize) : ''}</section>
<div class="col"><section class="c"><h3><span>Users</span><span style="text-transform:none;letter-spacing:0;font-weight:500"></span></h3>
${users.map((u) => `<div class="hr" ${u.active ? '' : 'style="opacity:.55"'}><span>${esc(u.name)} <span class="mu">${esc(u.username)}</span>${u.active ? '' : ' <span class="mu">(inactive)</span>'}</span><span class="row">${roleBadge(u.role)}${can.admin ? `<button class="btn sm g0" type="button" data-edit="${u.id}">Edit</button>` : ''}</span></div>`).join('')}
<div class="ft"><button class="btn p" type="button" data-invite ${can.admin ? '' : 'disabled title="Requires admin role"'}>+ Invite user</button></div></section>
<section class="c"><h3><span>Configuration</span><span style="text-transform:none;letter-spacing:0;font-weight:500"></span></h3>
<div class="hr"><span>Event retention</span>${can.admin ? `<select class="in sm" data-retention aria-label="Event retention">${options(RETENTION.map((d) => [d, `${d} days`]), settings.retention_days)}</select>` : `<span class="m">${settings.retention_days} days</span>`}</div>
<div class="hr"><span>Email notifications${settings.smtp_configured ? '' : ' <span class="mu" title="Set SMTP_URL to deliver email">(SMTP not set)</span>'}</span>${toggle(settings.email_notifications, { label: 'Email notifications', attrs: 'data-set="email_notifications"', disabled: !can.admin, title: can.admin ? '' : 'Requires admin role' })}</div>
<div class="hr"><span>Auto-block repeat offenders</span>${toggle(settings.auto_block, { label: 'Auto-block repeat offenders', attrs: 'data-set="auto_block"', disabled: !can.admin, title: can.admin ? '' : 'Requires admin role' })}</div>
<div class="hr"><span>API key</span><span class="row"><span class="m">${esc(settings.api_key_hint)}</span>${can.admin ? '<button class="btn sm g0" type="button" data-rotate>Rotate</button>' : ''}</span></div></section></div></div>`;
  }

  async function refresh() { await load(); render(); }

  function invite() {
    modal({
      title: 'Invite user', submitLabel: 'Create user',
      html: `${field('Full name', '<input class="in" name="name" maxlength="60" required>')}${field('Username', '<input class="in" name="username" maxlength="30" placeholder="j.doe" autocapitalize="none" required>')}${field('Email (optional)', '<input class="in" name="email" type="email">')}${field('Role', `<select class="in" name="role">${options([['viewer', 'Viewer: read only'], ['analyst', 'Analyst: alerts and rules'], ['admin', 'Admin: everything']], 'viewer')}</select>`)}`,
      onSubmit: async (fd, close, form) => {
        const r = await post('/users', Object.fromEntries([...fd.entries()]));
        form.querySelector('.mb').innerHTML = `<p style="margin-top:0">User <b>${esc(r.username)}</b> created. Email is not sent automatically; share this temporary password directly. They must change it at first sign-in.</p>${secretBox('Temporary password', r.temporaryPassword)}`;
        form.querySelector('[type=submit]').remove();
        form.querySelector('[data-close]').textContent = 'Done';
        await refresh();
      },
    });
  }

  function edit(u) {
    modal({
      title: `Edit ${u.username}`, submitLabel: 'Save changes',
      html: `${field('Full name', `<input class="in" name="name" value="${esc(u.name)}" maxlength="60" required>`)}${field('Role', `<select class="in" name="role">${options([['viewer', 'Viewer'], ['analyst', 'Analyst'], ['admin', 'Admin']], u.role)}</select>`)}
<label class="fld chk"><input type="checkbox" name="active" ${u.active ? 'checked' : ''}> Account active</label>
<div style="margin-top:8px"><button type="button" class="btn sm" data-reset>Reset password…</button></div><div id="rp"></div>`,
      onMount: (form) => {
        form.querySelector('[data-reset]').addEventListener('click', async (e) => {
          try { const r = await patch(`/users/${u.id}`, { resetPassword: true }); form.querySelector('#rp').innerHTML = secretBox('New temporary password', r.temporaryPassword); e.target.disabled = true; } catch (ex) { toast(ex.message, 'err'); }
        });
      },
      onSubmit: async (fd, close) => {
        const body = {};
        if (fd.get('name') !== u.name) body.name = fd.get('name');
        if (fd.get('role') !== u.role) body.role = fd.get('role');
        const active = fd.get('active') === 'on';
        if (active !== u.active) body.active = active;
        if (Object.keys(body).length) await patch(`/users/${u.id}`, body);
        close(); toast('User updated'); await refresh();
      },
    });
  }

  await load(); render();

  root.addEventListener('change', async (e) => {
    const t = e.target;
    if (t.matches('[data-retention]')) {
      try { settings = await patch('/settings', { retention_days: Number(t.value) }); toast(`Retention set to ${t.value} days`); await refresh(); } catch (ex) { toast(ex.message, 'err'); }
    }
  });
  root.addEventListener('click', async (e) => {
    const t = e.target;
    const sg = t.closest('[data-seg]'); if (sg) { S.range = sg.dataset.seg; S.page = 1; await refresh(); return; }
    const pg = t.closest('[data-pg]'); if (pg && !pg.disabled) { S.page = Number(pg.dataset.pg); await refresh(); return; }
    if (t.closest('[data-export]')) { window.location.href = '/api/audit/export.csv' + qs({ range: S.range, tz: tz() }); return; }
    if (t.closest('[data-invite]')) { invite(); return; }
    const ed = t.closest('[data-edit]'); if (ed) { edit(users.find((u) => u.id === Number(ed.dataset.edit))); return; }
    const st = t.closest('[data-set]');
    if (st) { const k = st.dataset.set; try { settings = await patch('/settings', { [k]: !settings[k] }); await refresh(); } catch (ex) { toast(ex.message, 'err'); } return; }
    if (t.closest('[data-rotate]')) {
      modal({
        title: 'Rotate API key', submitLabel: 'Rotate key', danger: true,
        html: '<p class="mu" style="margin-top:0">A new sensor ingest key is generated and the current one stops working immediately.</p><div id="nk"></div>',
        onSubmit: async (_fd, _close, form) => {
          const r = await post('/settings/rotate-api-key');
          form.querySelector('#nk').innerHTML = secretBox('New API key', r.apiKey);
          form.querySelector('[type=submit]').remove(); form.querySelector('[data-close]').textContent = 'Done';
          await refresh();
        },
      });
      return;
    }
    const cp = t.closest('[data-copy]');
    if (cp) { try { await navigator.clipboard.writeText(cp.dataset.copy); toast('Copied'); } catch { toast('Copy failed: select the text manually', 'err'); } }
  });
  document.addEventListener('click', copyHandler);
  function copyHandler(e) {
    const cp = e.target.closest('.ov [data-copy]');
    if (cp) navigator.clipboard.writeText(cp.dataset.copy).then(() => toast('Copied'), () => toast('Copy failed: select the text manually', 'err'));
  }
  return { live: () => {}, destroy: () => document.removeEventListener('click', copyHandler) };
}
