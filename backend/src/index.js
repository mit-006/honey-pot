import { createApp } from "./app.js";
import { createAuth } from "./auth.js";
import { loadConfig } from "./config.js";
import { audit, getSetting, openDb, redact } from "./db.js";
import { createEngine } from "./services/engine.js";
import { createNotifier } from "./services/notify.js";
import { isEmpty, seedBase, seedHistory } from "./services/seed.js";
import { startSimulator } from "./services/simulator.js";

export async function build(config = loadConfig(), { log = console } = {}) {
  const db = await openDb(config);
  const notifier = createNotifier(config);
  const engine = createEngine({ db, config, notifier });
  const auth = createAuth({ db, config });
  let firstKey = null;
  if (config.seedOnEmpty && (await isEmpty(db))) {
    log.log(
      `[seed] empty database: creating demo users, decoys, rules and ${config.seedDays} days of SIMULATED history…`,
    );
    const t0 = Date.now();
    firstKey = await seedBase(db, config);
    const { events } = await seedHistory(db, engine, { days: config.seedDays });
    log.log(
      `[seed] ${events} synthetic events in ${((Date.now() - t0) / 1000).toFixed(1)}s. Ingest API key (shown once): ${firstKey}`,
    );
  }
  const app = createApp({ db, config, engine, auth });
  return { db, engine, auth, app, config, firstKey };
}

/** Retention purge + expired session cleanup. */
export async function maintenance(ctx) {
  const days = Number(await getSetting(ctx.db, "retention_days", 90));
  const cutoff = Date.now() - days * 86400e3;
  const e = (await ctx.db.run("DELETE FROM events WHERE ts < ?", cutoff))
    .changes;
  await ctx.db.run("DELETE FROM rule_hits WHERE ts < ?", cutoff);
  await ctx.db.run(
    "DELETE FROM notifications WHERE ts < ? AND is_read = 1",
    cutoff,
  );
  await ctx.auth.purgeSessions();
  if (e)
    await audit(ctx.db, {
      user: "system",
      action: "Retention purge",
      target: `${e} events > ${days} days`,
    });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  let ctx;
  try {
    ctx = await build();
  } catch (e) {
    console.error(`\n[startup failed] ${e.message}\n`);
    process.exit(1);
  }
  const { config } = ctx;
  await maintenance(ctx).catch((e) => console.warn("[maintenance]", e.message));
  setInterval(
    () =>
      maintenance(ctx).catch((e) => console.warn("[maintenance]", e.message)),
    3600e3,
  ).unref();
  if (config.simulatorEnabled)
    startSimulator({ engine: ctx.engine, db: ctx.db, config });
  const server = ctx.app.listen(config.port, config.host, () => {
    console.log(
      `Honeypot Atlas API listening on http://${config.host}:${config.port}  (database: ${redact(config.databaseUrl)})`,
    );
    console.log(
      config.simulatorEnabled
        ? "Mode: SIMULATED telemetry (no real sockets opened, nothing scanned)."
        : "Mode: simulator off.",
    );
    if (config.ingestEnabled)
      console.log(
        "WARNING: sensor ingest is ENABLED. Keep sensors isolated and authorised.",
      );
    if (config.host === "0.0.0.0")
      console.log(
        "NOTE: API bound to all interfaces; only the web tier should be able to reach this port.",
      );
  });
  const stop = () => {
    server.close(async () => {
      await ctx.db.close().catch(() => {});
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 4000).unref();
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
