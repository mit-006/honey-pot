import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { PASSWORD, startApp } from './helpers.mjs';
import crypto from 'node:crypto';

describe('API: authentication and access control', () => {
  let app, admin, analyst, viewer;
  before(async () => {
    app = await startApp();
    [admin, analyst, viewer] = await Promise.all([app.as('a.rivera'), app.as('s.kapoor'), app.as('m.chen')]);
  });
  after(() => app.close());

  it('rejects unauthenticated requests', async () => {
    const c = app.client();
    assert.equal((await c.call('GET', '/overview')).status, 401);
    assert.equal((await c.call('GET', '/alerts')).status, 401);
    assert.equal((await c.call('GET', '/health')).status, 200);
  });

  it('requires the CSRF header and a same-origin Origin on mutations', async () => {
    const res = await fetch(`${app.base}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'a.rivera', password: PASSWORD }) });
    assert.equal(res.status, 403);
    const c = app.client();
    const r = await c.call('POST', '/auth/login', { username: 'a.rivera', password: PASSWORD }, { origin: 'https://evil.example' });
    assert.equal(r.status, 403);
  });

  it('sets an HttpOnly SameSite=Strict session cookie and never returns the hash', async () => {
    const res = await fetch(`${app.base}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-atlas-csrf': '1' }, body: JSON.stringify({ username: 'a.rivera', password: PASSWORD }) });
    const cookie = res.headers.get('set-cookie');
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Strict/);
    assert.ok(!JSON.stringify(await res.json()).includes('scrypt'));
  });

  it('throttles repeated failed logins', async () => {
    const c = app.client();
    let last;
    const wrong = crypto.randomBytes(8).toString('hex');
    for (let i = 0; i < 9; i++) last = await c.login('throttle.me', wrong);
    assert.equal(last.status, 429);
  });

  it('enforces roles: viewer < analyst < admin', async () => {
    const alert = (await admin('GET', '/alerts?status=open')).json.rows[0];
    assert.equal((await viewer('POST', `/alerts/${alert.id}/acknowledge`)).status, 403);
    assert.equal((await analyst('POST', `/alerts/${alert.id}/acknowledge`)).status, 200);
    assert.equal((await viewer('POST', '/rules', {})).status, 403);
    const decoy = { name: 'ssh-new-01', protocol: 'SSH', host: '10.20.9.1', segment: 'DMZ' };
    assert.equal((await analyst('POST', '/decoys', decoy)).status, 403);
    assert.equal((await admin('POST', '/decoys', decoy)).status, 201);
    assert.equal((await analyst('POST', '/users', { name: 'X Y', username: 'x.y', role: 'viewer' })).status, 403);
    assert.equal((await analyst('PATCH', '/settings', { auto_block: true })).status, 403);
  });
});

describe('API: workflows', () => {
  let app, admin, analyst;
  before(async () => { app = await startApp(); [admin, analyst] = await Promise.all([app.as('a.rivera'), app.as('s.kapoor')]); });
  after(() => app.close());

  it('alert lifecycle: acknowledge, resolve, and conflict on repeats', async () => {
    const a = (await analyst('GET', '/alerts?status=open')).json.rows[0];
    const before = (await analyst('GET', '/alerts/counts')).json;
    assert.equal((await analyst('POST', `/alerts/${a.id}/acknowledge`)).status, 200);
    assert.equal((await analyst('POST', `/alerts/${a.id}/acknowledge`)).status, 409);
    assert.equal((await analyst('POST', `/alerts/${a.id}/resolve`)).status, 200);
    assert.equal((await analyst('POST', `/alerts/${a.id}/resolve`)).status, 409);
    const after = (await analyst('GET', '/alerts/counts')).json;
    assert.equal(after.open, before.open - 1);
    const audit = (await admin('GET', '/audit?range=7d&pageSize=100')).json.rows;
    assert.ok(audit.some((r) => r.action === 'Resolved alert' && r.target === `ALT-${String(a.id).padStart(4, '0')}`));
  });

  it('bulk actions report done and skipped', async () => {
    const rows = (await analyst('GET', '/alerts?status=open&pageSize=100')).json.rows.slice(0, 3);
    await analyst('POST', `/alerts/${rows[0].id}/resolve`);
    const r = await analyst('POST', '/alerts/bulk', { ids: rows.map((x) => x.id), action: 'resolve' });
    assert.deepEqual([r.json.done, r.json.skipped], [2, 1]);
    assert.equal((await analyst('POST', '/alerts/bulk', { ids: [], action: 'resolve' })).status, 400);
  });

  it('events: filter, paginate, detail, create alert, block IP', async () => {
    const list = (await admin('GET', '/events?range=7d&severity=critical&pageSize=5')).json;
    assert.ok(list.rows.every((e) => e.severity === 'critical'));
    assert.ok(list.rows.length <= 5);
    const search = (await admin('GET', `/events?range=7d&q=${list.rows[0].src_ip}`)).json;
    assert.ok(search.rows.every((e) => e.src_ip === list.rows[0].src_ip));
    const id = list.rows[0].id;
    const d = (await admin('GET', `/events/${id}`)).json;
    assert.equal(d.id, id);
    assert.equal((await analyst('POST', `/events/${id}/alert`)).status, 201);
    assert.equal((await analyst('POST', `/events/${id}/alert`)).status, 409);
    assert.equal((await analyst('POST', `/events/${id}/block-ip`)).json.blocked, true);
    assert.equal((await admin('GET', `/events/${id}`)).json.blocked, true);
    assert.equal((await analyst('DELETE', `/events/${id}/block-ip`)).json.blocked, false);
    assert.equal((await admin('GET', '/events/99999999')).status, 404);
  });

  it('CSV export neutralises spreadsheet formulas', async () => {
    await app.engine.ingest({ decoy: 'web-admin-02', src_ip: '203.0.113.99', type_key: 'http.sqli', summary: '=HYPERLINK("http://x.test")', payload: 'x' });
    const r = await admin('GET', '/events/export.csv?range=1h&q=203.0.113.99');
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type'), /text\/csv/);
    assert.ok(r.text.includes(`"'=HYPERLINK`), r.text);
  });

  it('rules: create, validate, edit, toggle, test, delete', async () => {
    const body = { name: 'Redis recon', code: 'redis-rc', match_type: 'redis.info', metric: 'count', op: '>=', threshold: 2, window_s: 120, severity: 'low' };
    const c = await analyst('POST', '/rules', body);
    assert.equal(c.status, 201);
    assert.equal((await analyst('POST', '/rules', body)).status, 409);
    assert.equal((await analyst('POST', '/rules', { ...body, name: 'Bad', match_type: 'nope' })).status, 400);
    assert.equal((await analyst('POST', '/rules', { ...body, name: 'Bad2', threshold: -1 })).status, 400);
    assert.equal((await analyst('PATCH', `/rules/${c.json.id}`, { threshold: 4 })).status, 200);
    assert.equal((await analyst('PATCH', `/rules/${c.json.id}`, { enabled: false })).status, 200);
    const t = await analyst('POST', `/rules/${c.json.id}/test`, {});
    assert.equal(t.status, 200);
    assert.ok('hits' in t.json && 'alerts' in t.json);
    const listed = (await analyst('GET', '/rules')).json;
    const mine = listed.rules.find((r) => r.id === c.json.id);
    assert.equal(mine.threshold, 4);
    assert.equal(mine.enabled, false);
    assert.equal((await analyst('DELETE', `/rules/${c.json.id}`)).status, 403);
    assert.equal((await admin('DELETE', `/rules/${c.json.id}`)).status, 200);
  });

  it('decoys: validation, duplicate names, pause, stats, delete', async () => {
    assert.equal((await admin('POST', '/decoys', { name: 'Bad Name', protocol: 'SSH', host: '10.0.0.1', segment: 'X' })).status, 400);
    assert.equal((await admin('POST', '/decoys', { name: 'ssh-dmz-01', protocol: 'SSH', host: '10.0.0.1', segment: 'X' })).status, 409);
    assert.equal((await admin('POST', '/decoys', { name: 'ok-decoy', protocol: 'SSH', host: '10.0.0.1', port: 70000, segment: 'X' })).status, 400);
    const c = await admin('POST', '/decoys', { name: 'smb-test-01', protocol: 'SMB', host: '10.0.0.5', segment: 'Lab' });
    assert.equal(c.status, 201);
    assert.equal(c.json.port, 445, 'default port by protocol');
    assert.equal((await admin('PATCH', `/decoys/${c.json.id}`, { enabled: false })).status, 200);
    const list = (await admin('GET', '/decoys?status=paused')).json;
    assert.ok(list.decoys.some((d) => d.name === 'smb-test-01'));
    await assert.rejects(app.engine.ingest({ decoy: 'smb-test-01', src_ip: '192.0.2.1', type_key: 'smb.enum' }), /disabled/);
    assert.equal((await admin('DELETE', `/decoys/${c.json.id}`)).status, 200);
    const all = (await admin('GET', '/decoys')).json;
    assert.equal(all.decoys.length, 16);
    assert.equal(all.decoys[0].bars.length, 24);
  });

  it('overview and analytics return consistent aggregates', async () => {
    const o = (await admin('GET', '/overview?range=7d')).json;
    const a = (await admin('GET', '/analytics?range=7d&tz=0')).json;
    const total = (await app.db.get('SELECT COUNT(*) AS c FROM events WHERE ts > ?', o.from)).c;
    assert.ok(Math.abs(o.kpis.events.value - total) <= 2);
    assert.equal(o.trend.values.reduce((s, x) => s + x, 0), o.kpis.events.value);
    assert.equal(a.heatmap.length, 7);
    assert.equal(a.heatmap[0].length, 24);
    assert.ok(a.kpis.detection.value > 0 && a.kpis.detection.value <= 100);
  });

  it('users: invite, forced password change, last-admin guard, deactivate', async () => {
    const inv = await admin('POST', '/users', { name: 'New Person', username: 'n.person', email: 'n@x.test', role: 'analyst' });
    const NEW_PW = crypto.randomBytes(12).toString('hex'); // 24 chars, passes the 10+ rule
    assert.equal(inv.status, 201);
    assert.ok(inv.json.temporaryPassword.length > 10);
    assert.equal((await admin('POST', '/users', { name: 'Dup', username: 'n.person', role: 'viewer' })).status, 409);
    const c = app.client();
    const login = await c.login('n.person', inv.json.temporaryPassword);
    assert.equal(login.json.user.must_change, true);
    assert.equal((await c.call('POST', '/auth/password', { current: inv.json.temporaryPassword, next: 'short' })).status, 400);
    assert.equal((await c.call('POST', '/auth/password', { current: 'wrong-wrong-1', next: NEW_PW })).status, 403);
    assert.equal((await c.call('POST', '/auth/password', { current: inv.json.temporaryPassword, next: NEW_PW })).status, 200);
    const me = await c.call('GET', '/auth/me');
    assert.equal(me.json.user.must_change, false);
    const users = (await admin('GET', '/users')).json;
    const self = users.find((u) => u.username === 'a.rivera');
    assert.equal((await admin('PATCH', `/users/${self.id}`, { role: 'viewer' })).status, 409);
    assert.equal((await admin('PATCH', `/users/${self.id}`, { active: false })).status, 409);
    const np = users.find((u) => u.username === 'n.person');
    assert.equal((await admin('PATCH', `/users/${np.id}`, { active: false })).status, 200);
    assert.equal((await c.call('GET', '/overview')).status, 401, 'sessions are revoked on deactivation');
    assert.equal((await app.client().login('n.person', NEW_PW)).status, 401);
  });

  it('settings: validation, persistence and API key rotation', async () => {
    assert.equal((await admin('PATCH', '/settings', { retention_days: 7 })).status, 400);
    const s = await admin('PATCH', '/settings', { retention_days: 180, auto_block: true });
    assert.equal(s.json.retention_days, 180);
    assert.equal(s.json.auto_block, true);
    const hintBefore = s.json.api_key_hint;
    const k = await admin('POST', '/settings/rotate-api-key');
    assert.match(k.json.apiKey, /^hpa_/);
    assert.notEqual((await admin('GET', '/settings')).json.api_key_hint, hintBefore);
    assert.ok(!JSON.stringify((await admin('GET', '/settings')).json).includes(k.json.apiKey), 'full key is never readable again');
  });

  it('notifications can be read and cleared', async () => {
    const n = (await admin('GET', '/notifications')).json;
    assert.ok(n.items.length > 0);
    await admin('POST', '/notifications/read');
    assert.equal((await admin('GET', '/notifications')).json.unread, 0);
  });
});

describe('API: sensor ingest safety', () => {
  it('is disabled by default (simulation only)', async () => {
    const app = await startApp({ history: false });
    const r = await app.client().call('POST', '/ingest', { decoy: 'ssh-dmz-01', src_ip: '192.0.2.1', type_key: 'ssh.brute_force' }, { 'x-api-key': app.apiKey });
    assert.equal(r.status, 403);
    assert.match(r.json.error, /disabled/i);
    await app.close();
  });

  it('when enabled, needs the API key and validates payloads', async () => {
    const app = await startApp({ history: false, env: { INGEST_ENABLED: 'true' } });
    const c = app.client();
    const ev = { decoy: 'ssh-dmz-01', src_ip: '192.0.2.77', type_key: 'ssh.brute_force', attempts: 40, payload: '<script>alert(1)</script>' };
    assert.equal((await c.call('POST', '/ingest', ev)).status, 401);
    assert.equal((await c.call('POST', '/ingest', ev, { 'x-api-key': 'hpa_wrong' })).status, 401);
    const ok = await c.call('POST', '/ingest', ev, { 'x-api-key': app.apiKey });
    assert.equal(ok.status, 202);
    assert.equal(ok.json.accepted, 1);
    assert.equal(ok.json.alerts, 1);
    const bad = await c.call('POST', '/ingest', { events: [{ ...ev, src_ip: 'x' }, ev] }, { 'x-api-key': app.apiKey });
    assert.equal(bad.json.accepted, 1);
    assert.equal(bad.json.errors.length, 1);
    const stored = await app.db.get("SELECT simulated, payload FROM events WHERE src_ip = '192.0.2.77' LIMIT 1");
    assert.equal(stored.simulated, 0, 'sensor events are not labelled simulated');
    assert.equal(stored.payload, '<script>alert(1)</script>', 'stored verbatim; the UI escapes on render');
    await app.close();
  });
});

describe('persistence (data tier)', () => {
  it('data survives a full restart of the application tier on the same database', async () => {
    const a = await startApp({ history: false });
    await a.engine.ingest({ decoy: 'ssh-dmz-01', src_ip: '203.0.113.5', type_key: 'ssh.brute_force', attempts: 50 });
    const admin = await a.as('a.rivera');
    await admin('PATCH', '/settings', { retention_days: 365 });
    await a.close({ drop: false }); // API process gone, PostgreSQL keeps the data
    const b = await startApp({ schema: a.schema, env: { SEED_ON_EMPTY: 'true' } });
    assert.equal((await b.db.get('SELECT COUNT(*) AS c FROM users')).c, 3, 'not re-seeded');
    assert.equal((await b.db.get("SELECT COUNT(*) AS c FROM events WHERE src_ip = '203.0.113.5'")).c, 1);
    assert.equal((await b.db.get("SELECT value FROM settings WHERE key = 'retention_days'")).value, '365');
    assert.equal((await b.db.get('SELECT COUNT(*) AS c FROM alerts')).c, 1);
    await b.close();
  });
});

describe('three-tier behaviour', () => {
  it('health reports database status and returns 503 when the data tier is unreachable', async () => {
    const app = await startApp({ history: false });
    const c = app.client();
    const ok = await c.call('GET', '/health');
    assert.equal(ok.status, 200);
    assert.equal(ok.json.database, 'up');
    await app.db.close(); // simulate PostgreSQL going away
    const down = await c.call('GET', '/health');
    assert.equal(down.status, 503);
    assert.deepEqual([down.json.api, down.json.database], ['up', 'down']);
    await app.close();
  });

  it('refuses to start against an empty database and explains how to apply the schema', async () => {
    const { loadConfig } = await import('../src/config.js');
    const { openDb } = await import('../src/db.js');
    const { TEST_DB } = await import('./helpers.mjs');
    const pg = (await import('pg')).default;
    const c = new pg.Client({ connectionString: TEST_DB }); await c.connect();
    await c.query('CREATE SCHEMA t_empty_check'); await c.end();
    await assert.rejects(openDb(loadConfig({ DATABASE_URL: TEST_DB, DB_SCHEMA: 't_empty_check' })), /Apply the schema first/);
    const c2 = new pg.Client({ connectionString: TEST_DB }); await c2.connect();
    await c2.query('DROP SCHEMA t_empty_check CASCADE'); await c2.end();
  });

  it('reports a clear error when the database host is wrong', async () => {
    const { loadConfig } = await import('../src/config.js');
    const { openDb } = await import('../src/db.js');
    const badUrl = new URL('postgres://127.0.0.1:1/atlas');
    badUrl.username = 'atlas';
    badUrl.password = crypto.randomBytes(8).toString('hex');
    await assert.rejects(openDb(loadConfig({ DATABASE_URL: badUrl.toString() })), /Cannot reach the database tier/);
  });

  it('uses the client IP forwarded by the trusted reverse proxy in the audit log', async () => {
    const app = await startApp({ history: false });
    const c = app.client({ 'x-forwarded-for': '198.51.100.9' });
    assert.equal((await c.login('a.rivera')).status, 200);
    const row = await app.db.get("SELECT ip FROM audit_log WHERE action = 'Signed in' ORDER BY id DESC LIMIT 1");
    assert.equal(row.ip, '198.51.100.9');
    await app.close();
  });

  it('is API-only by default: no static files, JSON at /', async () => {
    const app = await startApp({ history: false });
    const r = await fetch(`${app.base}/`);
    assert.equal((await r.json()).service, 'honeypot-atlas-api');
    assert.equal((await fetch(`${app.base}/index.html`)).status, 404);
    await app.close();
  });

  it('can serve the frontend directly in dev mode (FRONTEND_DIR)', async () => {
    const app = await startApp({ history: false, env: { FRONTEND_DIR: '../frontend' } });
    const r = await fetch(`${app.base}/`);
    assert.match(await r.text(), /Honeypot Atlas/);
    assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
    await app.close();
  });
});
