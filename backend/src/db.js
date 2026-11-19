import fs from 'node:fs';
import { AsyncLocalStorage } from 'node:async_hooks';
import pg from 'pg';

// BIGINT (int8) and NUMERIC come back as strings by default; every value here fits a JS double.
pg.types.setTypeParser(20, (v) => Number(v));
pg.types.setTypeParser(1700, (v) => Number(v));

const als = new AsyncLocalStorage(); // holds the transaction client while inside db.tx()
const toPg = (sql) => { let i = 0; return sql.replace(/\?/g, () => `$${++i}`); }; // write "?" placeholders, run $1..$n

/**
 * Thin async wrapper around a pg Pool.
 *   db.all(sql, ...params)  -> rows[]
 *   db.get(sql, ...params)  -> first row | undefined
 *   db.run(sql, ...params)  -> { changes, rows }   (use RETURNING to get generated ids)
 *   db.tx(async () => {...}) -> everything awaited inside runs on ONE connection in a transaction
 */
export function createDb(config) {
   if (!config.databaseUrl) {
    throw new Error('DATABASE_URL environment variable is required');
  }
  const pool = new pg.Pool({
    connectionString: config.databaseUrl,
    max: config.dbPoolMax,
    options: config.dbSchema ? `-c search_path=${config.dbSchema}` : undefined,
  });
  pool.on('error', (e) => console.error('[db] idle client error:', e.message));
  const exec = (sql, params) => (als.getStore() || pool).query(toPg(sql), params);

  const db = {
    pool,
    all: async (sql, ...p) => (await exec(sql, p)).rows,
    get: async (sql, ...p) => (await exec(sql, p)).rows[0],
    run: async (sql, ...p) => { const r = await exec(sql, p); return { changes: r.rowCount, rows: r.rows }; },
    async tx(fn) {
      if (als.getStore()) return fn(); // join the surrounding transaction
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const out = await als.run(client, fn);
        await client.query('COMMIT');
        return out;
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    },
    close: () => pool.end(),
  };
  return db;
}

export async function schemaReady(db) {
  const r = await db.get("SELECT to_regclass('users') AS t");
  return Boolean(r && r.t);
}

/** Connects, optionally applies database/schema.sql, and fails with a helpful message if the tables are missing. */
export async function openDb(config) {
  const db = createDb(config);
  try {
    await db.get('SELECT 1');
  } catch (e) {
    await db.close().catch(() => {});
    throw new Error(
      `Cannot reach the database tier (${redact(config.databaseUrl)}): ${e.message}`,
      { cause: e },
    );
  }
  if (config.autoMigrate) await db.pool.query(fs.readFileSync(config.schemaFile, 'utf8'));
  if (!(await schemaReady(db))) {
    await db.close().catch(() => {});
    throw new Error('The database is reachable but empty. Apply the schema first:\n  psql "$DATABASE_URL" -f ../database/schema.sql\n(or set AUTO_MIGRATE=true for development)');
  }
  return db;
}

export const redact = (url) => String(url).replace(/:\/\/([^:/@]+):[^@]*@/, '://$1:***@');
export const isUnique = (e) => e && e.code === '23505';

export async function getSetting(db, key, fallback = null) {
  const r = await db.get('SELECT value FROM settings WHERE key = ?', key);
  return r ? r.value : fallback;
}
export const setSetting = (db, key, value) =>
  db.run('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value', key, String(value));

export const audit = (db, { user = 'system', action, target = '', ip = '', ts = Date.now() }) =>
  db.run('INSERT INTO audit_log(ts,actor,action,target,ip) VALUES(?,?,?,?,?)', ts, user, action, target, ip);
