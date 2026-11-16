import express from 'express';
import { safeEqual, sha256 } from '../auth.js';
import { getSetting } from '../db.js';
import { HttpError, bad, oneOf } from '../util.js';

// Real-sensor intake. Disabled unless INGEST_ENABLED=true; always requires the API key.
export function ingestRouter({ db, config, engine }) {
  const r = express.Router();
  const hits = [];

  r.use(async (req, _res, next) => {
    if (!config.ingestEnabled) return next(new HttpError(403, 'Ingest is disabled (simulation-only mode). Set INGEST_ENABLED=true to accept sensor events.'));
    const key = String(req.headers['x-api-key'] || '');
    const expected = await getSetting(db, 'api_key_hash', '');
    if (!key || !expected || !safeEqual(sha256(key), expected)) return next(new HttpError(401, 'Invalid API key'));
    const now = Date.now();
    while (hits.length && hits[0] < now - 60e3) hits.shift();
    if (hits.length >= 6000) return next(new HttpError(429, 'Rate limit exceeded'));
    next();
  });

  r.post('/', async (req, res) => {
    const t0 = performance.now();
    const body = req.body || {};
    const list = Array.isArray(body.events) ? body.events : [body];
    if (!list.length || list.length > 500) throw bad('Send 1-500 events');
    let accepted = 0, alerts = 0;
    const errors = [];
    for (let i = 0; i < list.length; i++) {
      try { const out = await engine.ingest({ ...list[i], simulated: list[i].simulated === true }); accepted++; alerts += out.alerts.length; hits.push(Date.now()); }
      catch (err) { if (!err.status) throw err; errors.push({ index: i, error: err.message }); }
    }
    engine.metrics.gatewayAvgMs = engine.metrics.gatewayAvgMs * 0.9 + (performance.now() - t0) * 0.1;
    res.status(errors.length && !accepted ? 400 : 202).json({ accepted, alerts, errors });
  });

  r.post('/heartbeat', async (req, res) => {
    const { decoy, health } = req.body || {};
    oneOf(health, ['online', 'degraded'], 'health');
    const info = await db.run('UPDATE decoys SET health = ? WHERE name = ?', health, String(decoy || ''));
    if (!info.changes) throw new HttpError(404, 'Unknown decoy');
    engine.bus.emit('change', { kind: 'decoy' });
    res.json({ ok: true });
  });
  return r;
}
