import express from 'express';
import { DEFAULT_PORTS, PROTOCOLS } from '../catalog.js';
import { audit, isUnique } from '../db.js';
import { HttpError, bad, clientIp, oneOf, str } from '../util.js';

const HOST_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9]([a-z0-9.-]{0,60}[a-z0-9])?)$/i;
const statusOf = (d) => (!d.enabled ? 'paused' : d.health);

export async function decoyStats(db, now = Date.now()) {
  const hourStart = Math.floor(now / 3600e3) * 3600e3 - 23 * 3600e3;
  const agg = new Map((await db.all('SELECT decoy_id, COUNT(*) AS c, COUNT(DISTINCT src_ip) AS u FROM events WHERE ts > ? GROUP BY decoy_id', now - 24 * 3600e3)).map((r) => [r.decoy_id, r]));
  const last = new Map((await db.all('SELECT decoy_id, MAX(ts) AS t FROM events GROUP BY decoy_id')).map((r) => [r.decoy_id, r.t]));
  const bars = new Map();
  for (const r of await db.all(`SELECT decoy_id, FLOOR((ts - ?::bigint)::float8 / 3600000.0)::int AS b, COUNT(*) AS c FROM events WHERE ts >= ? GROUP BY decoy_id, b`, hourStart, hourStart)) {
    if (!bars.has(r.decoy_id)) bars.set(r.decoy_id, new Array(24).fill(0));
    bars.get(r.decoy_id)[Math.min(23, r.b)] = r.c;
  }
  return { agg, last, bars };
}

export function decoysRouter({ db, auth }) {
  const r = express.Router();
  const admin = auth.requireRole('admin');

  r.get('/', async (req, res) => {
    const now = Date.now();
    const { agg, last, bars } = await decoyStats(db, now);
    const all = (await db.all('SELECT * FROM decoys ORDER BY id')).map((d) => ({
      id: d.id, name: d.name, protocol: d.protocol, host: d.host, port: d.port, segment: d.segment, notes: d.notes,
      enabled: Boolean(d.enabled), health: d.health, status: statusOf(d),
      events24: (agg.get(d.id) || { c: 0 }).c, attackers24: (agg.get(d.id) || { u: 0 }).u,
      lastHit: last.get(d.id) || null, bars: bars.get(d.id) || new Array(24).fill(0),
    }));
    const filter = ['online', 'degraded', 'paused'].includes(req.query.status) ? req.query.status : 'all';
    const recent = await db.all('SELECT e.id, e.ts, d.name AS decoy, e.src_ip, e.summary FROM events e JOIN decoys d ON d.id = e.decoy_id ORDER BY e.ts DESC, e.id DESC LIMIT 5');
    res.json({
      total: all.length, segments: new Set(all.map((d) => d.segment)).size,
      counts: { all: all.length, online: all.filter((d) => d.status === 'online').length, degraded: all.filter((d) => d.status === 'degraded').length, paused: all.filter((d) => d.status === 'paused').length },
      decoys: filter === 'all' ? all : all.filter((d) => d.status === filter), recent, now,
    });
  });

  function validate(body, existing = null) {
    const out = {};
    if (!existing || body.name !== undefined) {
      out.name = str(body.name, 'name', { min: 3, max: 40 }).toLowerCase();
      if (!/^[a-z0-9][a-z0-9-]*$/.test(out.name)) throw bad('name may only contain lowercase letters, digits and dashes');
    }
    if (!existing || body.protocol !== undefined) out.protocol = oneOf(body.protocol, PROTOCOLS, 'protocol');
    if (!existing || body.host !== undefined) {
      out.host = str(body.host, 'host', { max: 62 });
      if (!HOST_RE.test(out.host)) throw bad('host must be an IPv4 address or hostname');
      if (/^\d+(\.\d+){3}$/.test(out.host) && out.host.split('.').some((o) => Number(o) > 255)) throw bad('invalid IPv4 address');
    }
    if (!existing || body.port !== undefined) {
      const proto = out.protocol || (existing && existing.protocol);
      out.port = body.port === undefined || body.port === '' || body.port === null ? DEFAULT_PORTS[proto] : Number(body.port);
      if (!Number.isInteger(out.port) || out.port < 1 || out.port > 65535) throw bad('port must be 1-65535');
    }
    if (!existing || body.segment !== undefined) out.segment = str(body.segment ?? 'DMZ', 'segment', { max: 20 });
    if (body.notes !== undefined) out.notes = String(body.notes).slice(0, 300);
    if (body.health !== undefined) out.health = oneOf(body.health, ['online', 'degraded'], 'health');
    if (body.enabled !== undefined) out.enabled = body.enabled ? 1 : 0;
    return out;
  }
  const conflict = (e) => { if (isUnique(e)) throw new HttpError(409, 'A decoy with that name already exists'); throw e; };

  r.post('/', admin, async (req, res) => {
    const v = validate(req.body || {});
    try {
      const row = await db.get('INSERT INTO decoys(name,protocol,host,port,segment,health,enabled,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?) RETURNING id',
        v.name, v.protocol, v.host, v.port, v.segment, v.health || 'online', v.enabled ?? 1, v.notes || '', Date.now());
      await audit(db, { user: req.user.username, action: 'Deployed decoy', target: v.name, ip: clientIp(req) });
      res.status(201).json({ id: row.id, ...v });
    } catch (e) { conflict(e); }
  });

  r.patch('/:id', admin, async (req, res) => {
    const id = Number(req.params.id);
    const d = await db.get('SELECT * FROM decoys WHERE id = ?', id);
    if (!d) throw new HttpError(404, 'Decoy not found');
    const v = validate(req.body || {}, d);
    const keys = Object.keys(v);
    if (!keys.length) throw bad('Nothing to update');
    try { await db.run(`UPDATE decoys SET ${keys.map((k) => `${k} = ?`).join(', ')} WHERE id = ?`, ...keys.map((k) => v[k]), id); } catch (e) { conflict(e); }
    const onlyToggle = keys.length === 1 && keys[0] === 'enabled';
    await audit(db, { user: req.user.username, action: onlyToggle ? (v.enabled ? 'Enabled decoy' : 'Paused decoy') : 'Edited decoy', target: v.name || d.name, ip: clientIp(req) });
    res.json({ ok: true });
  });

  r.delete('/:id', admin, async (req, res) => {
    const d = await db.get('SELECT name FROM decoys WHERE id = ?', Number(req.params.id));
    if (!d) throw new HttpError(404, 'Decoy not found');
    await db.run('DELETE FROM decoys WHERE id = ?', Number(req.params.id));
    await audit(db, { user: req.user.username, action: 'Deleted decoy', target: d.name, ip: clientIp(req) });
    res.json({ ok: true });
  });
  return r;
}
