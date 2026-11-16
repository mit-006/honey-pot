// npm run seed   -> seed demo data only if the database is empty
// npm run reset  -> TRUNCATE every table, then reseed (destructive!)
import { build } from '../src/index.js';
import { loadConfig } from '../src/config.js';
import { createDb } from '../src/db.js';

const config = loadConfig();
if (process.argv.includes('--reset')) {
  const db = createDb(config);
  await db.pool.query('TRUNCATE users, sessions, decoys, rules, events, rule_hits, alerts, audit_log, blocked_ips, notifications, settings RESTART IDENTITY CASCADE');
  await db.close();
  console.log('All tables truncated.');
}
config.seedOnEmpty = true;
const ctx = await build(config);
const n = (await ctx.db.get('SELECT COUNT(*) AS c FROM events')).c;
console.log(`Database ready (${n} events).`);
await ctx.db.close();
