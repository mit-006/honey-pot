import { DEFAULT_PORTS, SEED_DECOYS, SEED_RULES, conditionText } from '../catalog.js';
import { audit, setSetting } from '../db.js';
import { hashPassword, randomToken, sha256 } from '../auth.js';
import { activityFactor, buildAttackerPool, createGenerator, makeRng } from './simulator.js';

const USERS = [
  { username: 'a.rivera', name: 'Alex Rivera', email: 'a.rivera@atlas.example.test', role: 'admin', ip: '10.0.4.12' },
  { username: 's.kapoor', name: 'Sam Kapoor', email: 's.kapoor@atlas.example.test', role: 'analyst', ip: '10.0.4.31' },
  { username: 'm.chen', name: 'Min Chen', email: 'm.chen@atlas.example.test', role: 'viewer', ip: '10.0.5.8' },
];

export async function isEmpty(db) { return (await db.get('SELECT COUNT(*) AS c FROM users')).c === 0; }

/** Demo accounts, decoys, rules and settings. Returns the one-time sensor API key. */
export async function seedBase(db, config, now = Date.now()) {
  return db.tx(async () => {
    const pwHash = hashPassword(config.seedPassword);
    for (const u of USERS) {
      await db.run('INSERT INTO users(username,name,email,role,password_hash,created_at) VALUES(?,?,?,?,?,?)', u.username, u.name, u.email, u.role, pwHash, now - 40 * 86400e3);
    }
    for (const [name, protocol, host, segment, health, enabled] of SEED_DECOYS) {
      await db.run('INSERT INTO decoys(name,protocol,host,port,segment,health,enabled,created_at) VALUES(?,?,?,?,?,?,?,?)', name, protocol, host, DEFAULT_PORTS[protocol], segment, health, enabled, now - 40 * 86400e3);
    }
    for (const r of SEED_RULES) {
      await db.run(`INSERT INTO rules(name,code,match_type,metric,op,threshold,window_s,group_by,severity,notify,condition_text,enabled,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, r.name, r.code, r.match_type, r.metric, r.op, r.threshold, r.window_s, 'source_ip',
        r.severity, r.notify, r.condition_text || conditionText(r), r.name === 'Anonymous FTP login' ? 1 : r.enabled, now - 38 * 86400e3);
    }
    await setSetting(db, 'retention_days', 90);
    await setSetting(db, 'email_notifications', 1);
    await setSetting(db, 'auto_block', 0);
    const key = `hpa_${randomToken(24)}`;
    await setSetting(db, 'api_key_hash', sha256(key));
    await setSetting(db, 'api_key_hint', `hpa_••••${key.slice(-4)}`);
    return key;
  });
}

/** Generate `days` of synthetic history through the real engine, then assign realistic alert lifecycles. */
export async function seedHistory(db, engine, { days = 30, eventsPerDay = 1700, now = Date.now(), seed = 20261025 } = {}) {
  const rng = makeRng(seed);
  const gen = createGenerator({ rng, pool: buildAttackerPool(makeRng(seed)) });
  const decoys = await db.all('SELECT * FROM decoys');
  const start = now - days * 86400e3;
  const batch = [];
  const perHour = eventsPerDay / 24 / 1.25;
  for (let t = start; t < now; t += 3600e3) {
    const lam = perHour * activityFactor(t) * (1 + 0.25 * (t > now - 24 * 3600e3 ? 1 : 0)) * (0.85 + rng() * 0.3);
    const n = Math.round(lam);
    for (let i = 0; i < n; i++) {
      const ts = t + rng() * 3600e3;
      const live = decoys.filter((d) => d.enabled || ts < now - 26 * 3600e3);
      for (const e of gen.arrival({ decoys: live.map((d) => ({ ...d, enabled: 1 })), ts })) if (e.ts <= now - 2000) batch.push(e);
    }
  }
  batch.sort((a, b) => a.ts - b.ts);

  const ftpOff = now - 9 * 3600e3;
  const ftpRule = await db.get("SELECT id FROM rules WHERE name = 'Anonymous FTP login'");
  const rdp = await db.get("SELECT id FROM decoys WHERE name = 'rdp-jump-01'");
  await db.tx(async () => {
    await db.run('UPDATE decoys SET enabled = 1 WHERE id = ?', rdp.id); // paused in the final state, live during replay
    const cache = new Map((await db.all('SELECT * FROM decoys')).map((d) => [d.name, d]));
    const opts = { silent: true, decoys: cache, autoBlock: false };
    let ftpDisabled = false;
    for (const e of batch) {
      if (!ftpDisabled && e.ts >= ftpOff) {
        await db.run('UPDATE rules SET enabled = 0 WHERE id = ?', ftpRule.id);
        engine.invalidateRules();
        ftpDisabled = true;
      }
      try { await engine.ingest(e, opts); } catch (err) { if (!err.status) throw err; /* skip invalid synthetic record */ }
    }
    await db.run('UPDATE decoys SET enabled = 0 WHERE id = ?', rdp.id);
    await db.run('UPDATE rules SET enabled = 0 WHERE id = ?', ftpRule.id);
    engine.invalidateRules();
    await assignLifecycles(db, rng, now);
  });
  return { events: batch.length };
}

async function assignLifecycles(db, rng, now) {
  const users = await db.all("SELECT id, username FROM users WHERE role IN ('admin','analyst')");
  const ipOf = Object.fromEntries(USERS.map((u) => [u.username, u.ip]));
  const alerts = await db.all('SELECT id, created_at FROM alerts ORDER BY created_at');
  for (const a of alerts) {
    const age = now - a.created_at;
    const r = rng();
    let status;
    if (age < 3600e3) status = r < 0.9 ? 'open' : 'acknowledged';
    else if (age < 6 * 3600e3) status = r < 0.6 ? 'open' : r < 0.85 ? 'acknowledged' : 'resolved';
    else if (age < 24 * 3600e3) status = r < 0.25 ? 'open' : r < 0.45 ? 'acknowledged' : 'resolved';
    else status = r < 0.02 ? 'open' : r < 0.05 ? 'acknowledged' : 'resolved';
    const owner = status === 'open' ? (rng() < 0.3 ? rng.pick(users) : null) : rng.pick(users);
    let ackAt = null, resAt = null;
    if (status !== 'open') {
      ackAt = Math.min(now - 1000, a.created_at + Math.round((1 + rng() * 13) * 60e3));
      if (status === 'resolved') resAt = Math.min(now - 500, ackAt + Math.round((10 + rng() * 170) * 60e3));
    }
    await db.run('UPDATE alerts SET status=?, owner_id=?, acknowledged_at=?, resolved_at=? WHERE id = ?', status, owner ? owner.id : null, ackAt, resAt, a.id);
    const ref = `ALT-${String(a.id).padStart(4, '0')}`;
    if (owner && ackAt) await audit(db, { ts: ackAt, user: owner.username, action: 'Acknowledged alert', target: ref, ip: ipOf[owner.username] });
    if (owner && resAt) await audit(db, { ts: resAt, user: owner.username, action: 'Resolved alert', target: ref, ip: ipOf[owner.username] });
  }
  await db.run('UPDATE notifications SET is_read = 1');
  await db.run('UPDATE notifications SET is_read = 0 WHERE id IN (SELECT id FROM notifications ORDER BY ts DESC LIMIT 3)');

  const A = (hAgo, user, action, target) => audit(db, { ts: Math.round(now - hAgo * 3600e3), user, action, target, ip: ipOf[user] || '' });
  await A(0.2, 's.kapoor', 'Disabled rule', 'Port scan sweep');
  await A(0.9, 'a.rivera', 'Edited decoy', 'web-admin-02');
  await A(2.5, 'system', 'Rotated API key', 'Service account');
  await A(4, 'm.chen', 'Exported events', 'CSV · 24h');
  await A(5.1, 's.kapoor', 'Created rule', 'Web shell upload');
  await A(7, 'a.rivera', 'Changed retention', '90 days');
  await A(9, 's.kapoor', 'Disabled rule', 'Anonymous FTP login');
  await A(30 * 24, 'a.rivera', 'Invited user', 'm.chen');
  for (let d = 0; d < 30; d++) for (const u of USERS) {
    if (rng() < (u.role === 'viewer' ? 0.35 : 0.9)) await A(d * 24 + 1 + rng() * 10, u.username, 'Signed in', '');
  }
}
