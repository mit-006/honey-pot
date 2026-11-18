import crypto from 'node:crypto';
import fs from 'node:fs';
import pg from 'pg';
import { build } from '../src/index.js';
import { loadConfig } from '../src/config.js';
import { seedBase, seedHistory } from '../src/services/seed.js';

export const PASSWORD = crypto.randomBytes(16).toString('hex');
export const TEST_DB = process.env.TEST_DATABASE_URL;

if (!TEST_DB) {
  throw new Error('TEST_DATABASE_URL environment variable is required');
}

const quiet = { log() {}, warn() {}, error() {} };
const schemaSql = fs.readFileSync(new URL('../../database/schema.sql', import.meta.url), 'utf8');

async function adminQuery(sql) {
  const c = new pg.Client({ connectionString: TEST_DB });
  await c.connect();
  try { await c.query(sql); } finally { await c.end(); }
}

/** Each app gets its own PostgreSQL schema (a throw-away copy of the data tier) so tests never see each other's rows. */
export async function startApp({ env = {}, history = true, schema = null } = {}) {
  const name = schema || `t_${crypto.randomBytes(5).toString('hex')}`;
  if (!schema) await adminQuery(`CREATE SCHEMA ${name}; SET search_path TO ${name}; ${schemaSql}`);
  const config = loadConfig({ DATABASE_URL: TEST_DB, DB_SCHEMA: name, SEED_ON_EMPTY: 'false', SIMULATOR_ENABLED: 'false', SEED_PASSWORD: PASSWORD, ...env });
  const ctx = await build(config, { log: quiet });
  const apiKey = schema ? null : await seedBase(ctx.db, config);
  if (history && !schema) await seedHistory(ctx.db, ctx.engine, { days: 3, eventsPerDay: 500 });
  const server = ctx.app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;

  const client = (extraHeaders = {}) => {
    let cookie = '';
    const call = async (method, p, body, headers = {}) => {
      const res = await fetch(`${base}/api${p}`, { method, headers: { 'content-type': 'application/json', 'x-atlas-csrf': '1', ...extraHeaders, ...(cookie ? { cookie } : {}), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
      const sc = res.headers.get('set-cookie');
      if (sc) cookie = sc.split(';')[0];
      const text = await res.text();
      let json = null; try { json = JSON.parse(text); } catch { /* csv etc. */ }
      return { status: res.status, json, text, headers: res.headers };
    };
    return { call, login: (u, p = PASSWORD) => call('POST', '/auth/login', { username: u, password: p }) };
  };
  const as = async (user) => { const c = client(); const r = await c.login(user); if (r.status !== 200) throw new Error(`login ${user} failed: ${r.status}`); return c.call; };
  const stop = () => new Promise((r) => server.close(r));
  const close = async ({ drop = true } = {}) => { await stop(); await ctx.db.close().catch(() => {}); if (drop) await adminQuery(`DROP SCHEMA IF EXISTS ${name} CASCADE`); };
  return { ...ctx, server, base, client, as, apiKey, close, stop, schema: name };
}
