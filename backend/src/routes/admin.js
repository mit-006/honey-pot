import express from 'express';
import { hashPassword, randomToken, sha256, tempPassword, verifyPassword } from '../auth.js';
import { audit, getSetting, isUnique, setSetting } from '../db.js';
import { HttpError, bad, clientIp, csvRow, intParam, oneOf, str } from '../util.js';

const startOfDay = (now, tzMin) => { const off = tzMin * 60000; return now - ((((now + off) % 86400000) + 86400000) % 86400000); };

export function adminRouter({ db, config, auth }) {
  const r = express.Router();
  const admin = auth.requireRole('admin');

  // ---- audit log ----
  function auditFilter(q) {
    const now = Date.now();
    const range = ['today', '7d', '30d'].includes(q.range) ? q.range : 'today';
    const since = range === 'today' ? startOfDay(now, intParam(q.tz, 0, -840, 840)) : now - (range === '7d' ? 7 : 30) * 86400e3;
    return { since, range };
  }
  r.get('/audit', async (req, res) => {
    const { since, range } = auditFilter(req.query);
    const total = (await db.get('SELECT COUNT(*) AS c FROM audit_log WHERE ts >= ?', since)).c;
    const pageSize = intParam(req.query.pageSize, 10, 5, 100);
    const pages = Math.max(1, Math.ceil(total / pageSize));
    const page = Math.min(intParam(req.query.page, 1, 1, 1e6), pages);
    const rows = await db.all('SELECT id, ts, actor AS "user", action, target, ip FROM audit_log WHERE ts >= ? ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?', since, pageSize, (page - 1) * pageSize);
    res.json({ total, page, pages, pageSize, rows, range });
  });
  r.get('/audit/export.csv', async (req, res) => {
    const { since, range } = auditFilter(req.query);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="atlas-audit-${range}.csv"`);
    res.write(csvRow(['time_utc', 'user', 'action', 'target', 'ip']));
    for (const a of await db.all('SELECT * FROM audit_log WHERE ts >= ? ORDER BY ts DESC LIMIT 100000', since)) res.write(csvRow([new Date(a.ts).toISOString(), a.actor, a.action, a.target, a.ip]));
    await audit(db, { user: req.user.username, action: 'Exported audit log', target: `CSV · ${range}`, ip: clientIp(req) });
    res.end();
  });

  // ---- users ----
  r.get('/users', async (req, res) => {
    const isAdmin = req.user.role === 'admin';
    const rows = await db.all("SELECT id, username, name, email, role, active FROM users ORDER BY CASE role WHEN 'admin' THEN 0 WHEN 'analyst' THEN 1 ELSE 2 END, name");
    res.json(rows.map((u) => ({ id: u.id, username: u.username, name: u.name, role: u.role, active: Boolean(u.active), ...(isAdmin ? { email: u.email } : {}) })));
  });
  const USERNAME = /^[a-z][a-z0-9._-]{2,29}$/;
  r.post('/users', admin, async (req, res) => {
    const b = req.body || {};
    const username = str(b.username, 'username', { min: 3, max: 30 }).toLowerCase();
    if (!USERNAME.test(username)) throw bad('username must start with a letter and use a-z, 0-9, . _ -');
    const name = str(b.name, 'name', { min: 2, max: 60 });
    const email = b.email ? str(b.email, 'email', { max: 120 }) : '';
    if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw bad('email is not valid');
    const role = oneOf(b.role, ['admin', 'analyst', 'viewer'], 'role');
    const pw = tempPassword();
    try {
      await db.run('INSERT INTO users(username,name,email,role,password_hash,must_change,created_at) VALUES(?,?,?,?,?,1,?)', username, name, email, role, hashPassword(pw), Date.now());
    } catch (e) { if (isUnique(e)) throw new HttpError(409, 'That username is taken'); throw e; }
    await audit(db, { user: req.user.username, action: 'Invited user', target: username, ip: clientIp(req) });
    res.status(201).json({ username, temporaryPassword: pw });
  });
  r.patch('/users/:id', admin, async (req, res) => {
    const id = Number(req.params.id);
    const u = await db.get('SELECT * FROM users WHERE id = ?', id);
    if (!u) throw new HttpError(404, 'User not found');
    const b = req.body || {};
    const activeAdmins = async () => (await db.get("SELECT COUNT(*) AS c FROM users WHERE role='admin' AND active=1")).c;
    const out = {};
    if (b.role !== undefined) {
      const role = oneOf(b.role, ['admin', 'analyst', 'viewer'], 'role');
      if (u.role === 'admin' && role !== 'admin' && ((await activeAdmins()) <= 1 || id === req.user.id)) throw new HttpError(409, 'You cannot remove the last admin role (or your own)');
      await db.run('UPDATE users SET role = ? WHERE id = ?', role, id);
      await audit(db, { user: req.user.username, action: 'Changed user role', target: `${u.username} → ${role}`, ip: clientIp(req) });
    }
    if (b.name !== undefined) await db.run('UPDATE users SET name = ? WHERE id = ?', str(b.name, 'name', { min: 2, max: 60 }), id);
    if (b.active !== undefined) {
      if (!b.active && (id === req.user.id || (u.role === 'admin' && (await activeAdmins()) <= 1))) throw new HttpError(409, 'You cannot deactivate yourself or the last admin');
      await db.run('UPDATE users SET active = ? WHERE id = ?', b.active ? 1 : 0, id);
      if (!b.active) await db.run('DELETE FROM sessions WHERE user_id = ?', id);
      await audit(db, { user: req.user.username, action: b.active ? 'Reactivated user' : 'Deactivated user', target: u.username, ip: clientIp(req) });
    }
    if (b.resetPassword) {
      const pw = tempPassword();
      await db.run('UPDATE users SET password_hash = ?, must_change = 1 WHERE id = ?', hashPassword(pw), id);
      await db.run('DELETE FROM sessions WHERE user_id = ?', id);
      out.temporaryPassword = pw;
      await audit(db, { user: req.user.username, action: 'Reset password', target: u.username, ip: clientIp(req) });
    }
    res.json({ ok: true, ...out });
  });

  // ---- settings ----
  const readSettings = async () => ({
    retention_days: Number(await getSetting(db, 'retention_days', 90)),
    email_notifications: (await getSetting(db, 'email_notifications', '1')) === '1',
    auto_block: (await getSetting(db, 'auto_block', '0')) === '1',
    api_key_hint: await getSetting(db, 'api_key_hint', 'hpa_••••••••'),
    smtp_configured: Boolean(config.smtpUrl),
    ingest_enabled: config.ingestEnabled,
    simulator_enabled: config.simulatorEnabled,
  });
  r.get('/settings', async (_req, res) => res.json(await readSettings()));
  r.patch('/settings', admin, async (req, res) => {
    const b = req.body || {};
    const ip = clientIp(req), user = req.user.username;
    if (b.retention_days !== undefined) {
      const d = Number(b.retention_days);
      if (![30, 60, 90, 180, 365].includes(d)) throw bad('retention_days must be 30, 60, 90, 180 or 365');
      await setSetting(db, 'retention_days', d);
      await audit(db, { user, action: 'Changed retention', target: `${d} days`, ip });
    }
    for (const [k, label] of [['email_notifications', 'email notifications'], ['auto_block', 'auto-block']]) {
      if (b[k] !== undefined) { await setSetting(db, k, b[k] ? 1 : 0); await audit(db, { user, action: `${b[k] ? 'Enabled' : 'Disabled'} ${label}`, target: '', ip }); }
    }
    res.json(await readSettings());
  });
  r.post('/settings/rotate-api-key', admin, async (req, res) => {
    const key = `hpa_${randomToken(24)}`;
    await setSetting(db, 'api_key_hash', sha256(key));
    await setSetting(db, 'api_key_hint', `hpa_••••${key.slice(-4)}`);
    await audit(db, { user: req.user.username, action: 'Rotated API key', target: 'Service account', ip: clientIp(req) });
    res.json({ apiKey: key, hint: `hpa_••••${key.slice(-4)}` });
  });

  // ---- own password ----
  r.post('/auth/password', async (req, res) => {
    const { current, next } = req.body || {};
    const u = await db.get('SELECT * FROM users WHERE id = ?', req.user.id);
    if (!verifyPassword(String(current || ''), u.password_hash)) throw new HttpError(403, 'Current password is incorrect');
    if (typeof next !== 'string' || next.length < 10 || next.length > 128) throw bad('New password must be 10-128 characters');
    if (next === current) throw bad('New password must differ from the current one');
    await db.run('UPDATE users SET password_hash = ?, must_change = 0 WHERE id = ?', hashPassword(next), u.id);
    await db.run('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?', u.id, sha256(req.sessionToken));
    await audit(db, { user: u.username, action: 'Changed password', target: '', ip: clientIp(req) });
    res.json({ ok: true });
  });

  // ---- notifications ----
  r.get('/notifications', async (_req, res) => res.json({
    unread: (await db.get('SELECT COUNT(*) AS c FROM notifications WHERE is_read = 0')).c,
    items: await db.all('SELECT id, ts, severity, text, link, is_read AS read FROM notifications ORDER BY ts DESC, id DESC LIMIT 12'),
  }));
  r.post('/notifications/read', async (_req, res) => { await db.run('UPDATE notifications SET is_read = 1 WHERE is_read = 0'); res.json({ ok: true }); });

  return r;
}
