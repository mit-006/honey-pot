import express from "express";
import { audit } from "./db.js";
import { HttpError, clientIp } from "./util.js";
import { simulateBurst } from "./services/simulator.js";
import { adminRouter } from "./routes/admin.js";
import { alertsRouter } from "./routes/alerts.js";
import { dashboardRouter } from "./routes/dashboard.js";
import { decoysRouter } from "./routes/decoys.js";
import { eventsRouter } from "./routes/events.js";
import { ingestRouter } from "./routes/ingest.js";
import { rulesRouter } from "./routes/rules.js";

/** Application tier: JSON API only. The static frontend is served by Nginx (or FRONTEND_DIR in dev). */
export function createApp({ db, config, engine, auth }) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", config.trustProxy); // so req.ip is the real client when Nginx forwards X-Forwarded-For

  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "same-origin");
    next();
  });
  app.use(express.json({ limit: "1mb" }));

  if (config.frontendDir) {
    // dev/testing convenience only
    app.use((_req, res, next) => {
      res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      );
      res.setHeader("X-Frame-Options", "DENY");
      next();
    });
    app.use(express.static(config.frontendDir, { maxAge: 0 }));
  } else {
    app.get("/", (_req, res) =>
      res.json({
        service: "honeypot-atlas-api",
        note: "API tier only. Open the site through the web tier (Nginx).",
      }),
    );
  }

  const api = express.Router();
  api.use((_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  // ---- tier health: used by the demo to show each tier failing independently ----
  api.get("/health", async (_req, res) => {
    const t0 = performance.now();
    try {
      await db.get("SELECT 1");
      res.json({
        status: "ok",
        api: "up",
        database: "up",
        dbMs: Number((performance.now() - t0).toFixed(2)),
        simulator: config.simulatorEnabled,
      });
    } catch (e) {
      console.error("[health] db check failed:", e.message);
      res.status(503).json({ status: "degraded", api: "up", database: "down" });
    }
  });
  api.get("/meta", (_req, res) =>
    res.json({
      demoMode: config.demoMode,
      simulator: config.simulatorEnabled,
      ingestEnabled: config.ingestEnabled,
      version: "2.0.0",
    }),
  );

  api.use(auth.attach);
  api.use(auth.csrf);

  api.post("/auth/login", async (req, res) => {
    const { username, password } = req.body || {};
    const { user, token } = await auth.login(username, password, clientIp(req));
    res.setHeader("Set-Cookie", auth.cookieHeader(token, config.sessionTtlMs));
    await audit(db, {
      user: user.username,
      action: "Signed in",
      ip: clientIp(req),
    });
    res.json({
      user: {
        id: user.id,
        username: user.username,
        name: user.name,
        role: user.role,
        must_change: Boolean(user.must_change),
      },
    });
  });
  api.post("/auth/logout", async (req, res) => {
    await auth.logout(req.sessionToken);
    res.setHeader("Set-Cookie", auth.cookieHeader("", 0));
    res.json({ ok: true });
  });
  api.get("/auth/me", (req, res) => {
    if (!req.user) throw new HttpError(401, "Authentication required");
    const { id, username, name, role, must_change } = req.user;
    res.json({
      user: { id, username, name, role, must_change: Boolean(must_change) },
    });
  });

  api.use("/ingest", ingestRouter({ db, config, engine })); // API-key auth, no session

  api.use(auth.requireAuth);
  api.use("/", dashboardRouter({ db, engine }));
  api.use("/events", eventsRouter({ db, engine, auth }));
  api.use("/alerts", alertsRouter({ db, engine, auth }));
  api.use("/decoys", decoysRouter({ db, auth }));
  api.use("/rules", rulesRouter({ db, engine, auth }));
  api.use("/", adminRouter({ db, config, auth }));

  api.post("/simulator/burst", auth.requireRole("admin"), async (req, res) => {
    if (!config.simulatorEnabled)
      throw new HttpError(409, "Simulator is disabled");
    const n = Math.min(50, Math.max(1, Number((req.body || {}).n) || 5));
    const out = await simulateBurst({ engine, db, n });
    await audit(db, {
      user: req.user.username,
      action: "Triggered simulation burst",
      target: `${out.events} events`,
      ip: clientIp(req),
    });
    res.json(out);
  });

  api.get("/stream", (req, res) => {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-store",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });
    res.write("retry: 5000\n\n");
    const onChange = (m) =>
      res.write(`event: change\ndata: ${JSON.stringify(m)}\n\n`);
    engine.bus.on("change", onChange);
    const ping = setInterval(() => res.write(": ping\n\n"), 25000);
    req.on("close", () => {
      clearInterval(ping);
      engine.bus.off("change", onChange);
    });
  });

  api.use((_req, _res, next) => next(new HttpError(404, "Not found")));
  app.use("/api", api);

  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (err instanceof HttpError)
      return res.status(err.status).json({ error: err.message });
    if (err.type === "entity.parse.failed")
      return res.status(400).json({ error: "Invalid JSON" });
    if (err.type === "entity.too.large")
      return res.status(413).json({ error: "Payload too large" });
    console.error("[error]", err);
    res.status(500).json({ error: "Internal server error" });
  });
  return app;
}
