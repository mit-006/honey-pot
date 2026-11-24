// Applies ../database/schema.sql to DATABASE_URL (same file you can run with psql). Idempotent.
import fs from "node:fs";
import pg from "pg";
import { loadConfig } from "../src/config.js";
import { redact } from "../src/db.js";

const config = loadConfig();
const client = new pg.Client({ connectionString: config.databaseUrl });
await client.connect();
await client.query(fs.readFileSync(config.schemaFile, "utf8"));
await client.end();
const { hostname, port, pathname, protocol } = new URL(config.databaseUrl);
console.log(`Schema applied to ${protocol}//${hostname}:${port}${pathname}`);
