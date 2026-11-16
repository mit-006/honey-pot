import express from 'express';
import { audit } from '../db.js';
import { HttpError, SEVERITIES, bad, clientIp, intParam } from '../util.js';

const alertId = (id) => `ALT-${String(id).padStart(4, '0')}`;
const SEV_ORDER = "CASE a.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END";

export function alertsRouter({ db, engine, auth }) {
  const r = express.Router();
  const analyst = auth.requireRole('analyst');

  async function counts() {
    const c = await db.get(`SELECT COUNT(*) FILTER (WHERE status = 'open') AS open_n,
        COUNT(*) FILTER (WHERE status = 'acknowledged') AS ack_n,
        COUNT(*) FILTER (WHERE status = 'resolved' AND resolved_at > ?) AS res_n, COUNT(*) AS total FROM alerts`, Date.now() - 30 * 86400e3);
    return { open: c.open_n, acknowledged: c.ack_n, resolved30: c.res_n, total: c.total };
  }

  r.get('/counts', async (_req, res) => res.json(await counts()));

  r.get('/', async (req, res) => {
    const status = ['open', 'acknowledged', 'resolved', 'all'].includes(req.query.status) ? req.query.status : 'open';
    const where = [], params = [];
    if (status !== 'all') { where.push('a.status = ?'); params.push(status); }
    const sev = String(req.query.severity || '').split(',').filter((s) => SEVERITIES.includes(s));
    if (sev.length) { where.push(`a.severity IN (${sev.map(() => '?').join(',')})`); params.push(...sev); }
    const text = String(req.query.q || '').trim().toLowerCase().slice(0, 100);
    if (text) { where.push('(strpos(lower(a.title), ?) > 0 OR strpos(lower(a.code), ?) > 0 OR strpos(lower(a.src_ip), ?) > 0)'); params.push(text, text, text); }
    const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const total = (await db.get(`SELECT COUNT(*) AS c FROM alerts a ${w}`, ...params)).c;
    const pageSize = intParam(req.query.pageSize, 8, 5, 100);
    const pages = Math.max(1, Math.ceil(total / pageSize));
    const page = Math.min(intParam(req.query.page, 1, 1, 1e6), pages);
    const order = status === 'open' || status === 'acknowledged' ? `${SEV_ORDER} DESC, a.created_at DESC` : 'a.created_at DESC';
    const rows = await db.all(`SELECT a.id, a.code, a.title, a.severity, a.status, a.src_ip, a.created_at, a.acknowledged_at, a.resolved_at, a.event_id, a.manual,
      u.username AS owner, u.name AS owner_name, d.name AS decoy
      FROM alerts a LEFT JOIN users u ON u.id = a.owner_id LEFT JOIN decoys d ON d.id = a.decoy_id ${w}
      ORDER BY ${order}, a.id DESC LIMIT ? OFFSET ?`, ...params, pageSize, (page - 1) * pageSize);
    res.json({ total, page, pages, pageSize, rows: rows.map((a) => ({ ...a, ref: alertId(a.id) })), counts: await counts() });
  });

  async function transition(id, action, user, ip) {
    const a = await db.get('SELECT * FROM alerts WHERE id = ? FOR UPDATE', id);
    if (!a) throw new HttpError(404, 'Alert not found');
    const now = Date.now();
    if (action === 'acknowledge') {
      if (a.status !== 'open') throw new HttpError(409, `Alert is already ${a.status}`);
      await db.run("UPDATE alerts SET status='acknowledged', acknowledged_at=?, owner_id=COALESCE(owner_id, ?) WHERE id=?", now, user.id, id);
      await audit(db, { user: user.username, action: 'Acknowledged alert', target: alertId(id), ip });
    } else {
      if (a.status === 'resolved') throw new HttpError(409, 'Alert is already resolved');
      await db.run("UPDATE alerts SET status='resolved', resolved_at=?, acknowledged_at=COALESCE(acknowledged_at, ?), owner_id=COALESCE(owner_id, ?) WHERE id=?", now, now, user.id, id);
      await audit(db, { user: user.username, action: 'Resolved alert', target: alertId(id), ip });
    }
  }

  r.post('/bulk', analyst, async (req, res) => {
    const { ids, action } = req.body || {};
    if (!['acknowledge', 'resolve'].includes(action)) throw bad('action must be acknowledge or resolve');
    if (!Array.isArray(ids) || !ids.length || ids.length > 200) throw bad('ids must be 1-200 alert ids');
    let done = 0, skipped = 0;
    for (const id of ids) { // one transaction per alert so a skipped (conflicting) alert never aborts the rest
      try { await db.tx(() => transition(Number(id), action, req.user, clientIp(req))); done++; }
      catch (e) { if (e instanceof HttpError) skipped++; else throw e; }
    }
    engine.bus.emit('change', { kind: 'alert' });
    res.json({ done, skipped, counts: await counts() });
  });

  for (const [path, action] of [['acknowledge', 'acknowledge'], ['resolve', 'resolve']]) {
    r.post(`/:id/${path}`, analyst, async (req, res) => {
      await db.tx(() => transition(Number(req.params.id), action, req.user, clientIp(req)));
      engine.bus.emit('change', { kind: 'alert' });
      res.json({ ok: true, counts: await counts() });
    });
  }
  return r;
}
