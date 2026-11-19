import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bool = (v, d) =>
  v === undefined || v === ""
    ? d
    : ["1", "true", "yes", "on"].includes(String(v).toLowerCase());
const int = (v, d) =>
  v !== undefined && v !== "" && Number.isFinite(Number(v)) ? Number(v) : d;
const proxy = (v) => {
  if (v === undefined || v === "") return "loopback";
  if (["true", "1"].includes(v)) return true;
  if (["false", "0"].includes(v)) return false;
  return /^\d+$/.test(v) ? Number(v) : v;
};

export function loadConfig(env = process.env) {
  return {
    root,
    host: env.HOST || "127.0.0.1",
    port: int(env.PORT, 3000),
    databaseUrl: env.DATABASE_URL || "",
    dbSchema: env.DB_SCHEMA || "", // optional search_path (used by the tests for isolation)
    dbPoolMax: int(env.DB_POOL_MAX, 10),
    autoMigrate: bool(env.AUTO_MIGRATE, false),
    schemaFile: path.resolve(root, "../database/schema.sql"),
    trustProxy: proxy(env.TRUST_PROXY),
    sessionTtlMs: int(env.SESSION_TTL_HOURS, 12) * 3600 * 1000,
    cookieSecure: bool(env.COOKIE_SECURE, false),
    simulatorEnabled: bool(env.SIMULATOR_ENABLED, true),
    simulatorIntervalMs: int(env.SIMULATOR_INTERVAL_MS, 4000),
    ingestEnabled: bool(env.INGEST_ENABLED, false),
    demoMode: bool(env.DEMO_MODE, true),
    seedOnEmpty: bool(env.SEED_ON_EMPTY, true),
    seedDays: int(env.SEED_DAYS, 30),
    seedPassword: env.SEED_PASSWORD || "change-me-before-first-start",
    frontendDir: env.FRONTEND_DIR
      ? path.resolve(process.cwd(), env.FRONTEND_DIR)
      : "",
    smtpUrl: env.SMTP_URL || "",
    mailFrom: env.MAIL_FROM || "atlas@localhost",
  };
}
