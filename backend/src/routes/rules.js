import express from "express";
import { EVENT_TYPES, conditionText } from "../catalog.js";
import { audit, isUnique } from "../db.js";
import { HttpError, SEVERITIES, bad, clientIp, oneOf, str } from "../util.js";

const METRICS = ["count", "attempts", "distinct"];
const OPS = [">", ">="];
const SEV_ORDER =
  "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END";

export function rulesRouter({ db, engine, auth }) {
  const r = express.Router();
  const analyst = auth.requireRole("analyst");

  r.get("/meta", (_req, res) =>
    res.json({
      types: Object.entries(EVENT_TYPES).map(([key, t]) => ({
        key,
        label: t.label,
        protocol: t.protocol,
      })),
      metrics: METRICS,
      ops: OPS,
      severities: SEVERITIES,
    }),
  );

  r.get("/", async (req, res) => {
    const now = Date.now();
    const hits = new Map(
      (
        await db.all(
          "SELECT rule_id, COUNT(*) AS c FROM rule_hits WHERE ts > ? GROUP BY rule_id",
          now - 86400e3,
        )
      ).map((x) => [x.rule_id, x.c]),
    );
    const last = new Map(
      (
        await db.all(
          "SELECT rule_id, MAX(ts) AS t FROM rule_hits GROUP BY rule_id",
        )
      ).map((x) => [x.rule_id, x.t]),
    );
    let rules = (
      await db.all(
        `SELECT * FROM rules ORDER BY enabled DESC, ${SEV_ORDER} DESC, name`,
      )
    ).map((x) => ({
      ...x,
      enabled: Boolean(x.enabled),
      hits24: hits.get(x.id) || 0,
      lastHit: last.get(x.id) || null,
    }));
    const total = rules.length,
      enabled = rules.filter((x) => x.enabled).length;
    if (req.query.state === "enabled") rules = rules.filter((x) => x.enabled);
    if (req.query.state === "disabled") rules = rules.filter((x) => !x.enabled);
    const sev = String(req.query.severity || "")
      .split(",")
      .filter((s) => SEVERITIES.includes(s));
    if (sev.length) rules = rules.filter((x) => sev.includes(x.severity));
    const q = String(req.query.q || "")
      .trim()
      .toLowerCase();
    if (q)
      rules = rules.filter((x) =>
        `${x.name} ${x.code} ${x.condition_text}`.toLowerCase().includes(q),
      );
    res.json({ total, enabled, rules });
  });

  function validate(b, existing = null) {
    const o = {};
    const has = (k) => !existing || b[k] !== undefined;
    if (has("name")) o.name = str(b.name, "name", { min: 3, max: 60 });
    if (has("code")) {
      o.code = str(b.code, "code", { min: 3, max: 16 }).toUpperCase();
      if (!/^[A-Z0-9-]+$/.test(o.code))
        throw bad("code may only contain A-Z, 0-9 and dashes");
    }
    if (has("match_type")) {
      o.match_type = str(b.match_type, "match_type", { min: 3, max: 40 });
      if (!EVENT_TYPES[o.match_type]) throw bad("Unknown event type");
    }
    if (has("metric")) o.metric = oneOf(b.metric, METRICS, "metric");
    if (has("op")) o.op = oneOf(b.op, OPS, "op");
    if (has("threshold")) {
      o.threshold = Number(b.threshold);
      if (
        !Number.isInteger(o.threshold) ||
        o.threshold < 0 ||
        o.threshold > 1e6
      )
        throw bad("threshold must be an integer 0-1,000,000");
    }
    if (has("window_s")) {
      o.window_s = Number(b.window_s);
      if (!Number.isInteger(o.window_s) || o.window_s < 1 || o.window_s > 86400)
        throw bad("window must be 1-86400 seconds");
    }
    if (has("severity")) o.severity = oneOf(b.severity, SEVERITIES, "severity");
    if (b.notify !== undefined)
      o.notify = oneOf(b.notify, ["Dashboard", "Email + dashboard"], "notify");
    if (b.condition_text !== undefined)
      o.condition_text = String(b.condition_text).slice(0, 120);
    if (b.enabled !== undefined) o.enabled = b.enabled ? 1 : 0;
    return o;
  }
  const conflict = (e) => {
    if (isUnique(e))
      throw new HttpError(409, "A rule with that name already exists");
    throw e;
  };

  r.post("/", analyst, async (req, res) => {
    const v = validate(req.body || {});
    const m = { enabled: 1, notify: "Dashboard", ...v };
    if (!m.condition_text) m.condition_text = conditionText(m);
    try {
      const row = await db.get(
        `INSERT INTO rules(name,code,match_type,metric,op,threshold,window_s,group_by,severity,notify,condition_text,enabled,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`,
        m.name,
        m.code,
        m.match_type,
        m.metric,
        m.op,
        m.threshold,
        m.window_s,
        "source_ip",
        m.severity,
        m.notify,
        m.condition_text,
        m.enabled,
        Date.now(),
      );
      engine.invalidateRules();
      await audit(db, {
        user: req.user.username,
        action: "Created rule",
        target: m.name,
        ip: clientIp(req),
      });
      res.status(201).json({ id: row.id });
    } catch (e) {
      conflict(e);
    }
  });

  r.patch("/:id", analyst, async (req, res) => {
    const id = Number(req.params.id);
    const rule = await db.get("SELECT * FROM rules WHERE id = ?", id);
    if (!rule) throw new HttpError(404, "Rule not found");
    const v = validate(req.body || {}, rule);
    const keys = Object.keys(v);
    if (!keys.length) throw bad("Nothing to update");
    const structural = ["metric", "op", "threshold", "window_s"].some(
      (k) => k in v,
    );
    if (
      structural &&
      v.condition_text === undefined &&
      !/[A-Za-z_]+\.[A-Za-z_]+|_/.test(rule.condition_text)
    ) {
      v.condition_text = conditionText({ ...rule, ...v });
      keys.push("condition_text");
    }
    try {
      await db.run(
        `UPDATE rules SET ${keys.map((k) => `${k} = ?`).join(", ")} WHERE id = ?`,
        ...keys.map((k) => v[k]),
        id,
      );
    } catch (e) {
      conflict(e);
    }
    engine.invalidateRules();
    const onlyToggle = keys.length === 1 && keys[0] === "enabled";
    await audit(db, {
      user: req.user.username,
      action: onlyToggle
        ? v.enabled
          ? "Enabled rule"
          : "Disabled rule"
        : "Edited rule",
      target: v.name || rule.name,
      ip: clientIp(req),
    });
    engine.bus.emit("change", { kind: "rule" });
    res.json({ ok: true });
  });

  r.post("/:id/test", analyst, async (req, res) => {
    const rule = await db.get(
      "SELECT * FROM rules WHERE id = ?",
      Number(req.params.id),
    );
    if (!rule) throw new HttpError(404, "Rule not found");
    const draft = { ...rule, ...validate(req.body || {}, rule) };
    res.json({ ...(await engine.dryRun(draft)), windowH: 24 });
  });

  r.delete("/:id", auth.requireRole("admin"), async (req, res) => {
    const rule = await db.get(
      "SELECT name FROM rules WHERE id = ?",
      Number(req.params.id),
    );
    if (!rule) throw new HttpError(404, "Rule not found");
    await db.run("DELETE FROM rules WHERE id = ?", Number(req.params.id));
    engine.invalidateRules();
    await audit(db, {
      user: req.user.username,
      action: "Deleted rule",
      target: rule.name,
      ip: clientIp(req),
    });
    res.json({ ok: true });
  });
  return r;
}
