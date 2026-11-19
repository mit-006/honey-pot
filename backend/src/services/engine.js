import { EventEmitter } from "node:events";
import { EVENT_TYPES, severityFor } from "../catalog.js";
import { audit, getSetting } from "../db.js";
import { HttpError, SEVERITIES, bad, isIp } from "../util.js";

// One alert per rule+decoy per cooldown window (a "campaign" alert); every threshold crossing is still recorded as a rule hit.
export const ALERT_COOLDOWN_MS = 12 * 3600 * 1000;

export function createEngine({ db, notifier }) {
  const bus = new EventEmitter();
  bus.setMaxListeners(100);
  const metrics = {
    ingestAvgMs: 0,
    ingestSamples: 0,
    lastIngestAt: 0,
    lastRuleError: null,
    lastRuleErrorAt: 0,
    gatewayAvgMs: 0,
  };
  let rulesPromise = null;

  const loadRules = () => {
    if (!rulesPromise) {
      rulesPromise = db
        .all("SELECT * FROM rules WHERE enabled = 1")
        .then((rows) => {
          const m = new Map();
          for (const r of rows) {
            if (!m.has(r.match_type)) m.set(r.match_type, []);
            m.get(r.match_type).push(r);
          }
          return m;
        })
        .catch((e) => {
          rulesPromise = null;
          throw e;
        });
    }
    return rulesPromise;
  };
  const invalidateRules = () => {
    rulesPromise = null;
  };

  async function evaluate(rule, srcIp, ts) {
    const r = await db.get(
      `SELECT COUNT(*) AS c, COALESCE(SUM(attempts),0) AS a, COALESCE(SUM(distinct_n),0) AS d
      FROM events WHERE type_key = ? AND src_ip = ? AND ts > ? AND ts <= ?`,
      rule.match_type,
      srcIp,
      ts - rule.window_s * 1000,
      ts,
    );
    const value =
      rule.metric === "count" ? r.c : rule.metric === "attempts" ? r.a : r.d;
    return {
      value,
      passes:
        rule.op === ">" ? value > rule.threshold : value >= rule.threshold,
    };
  }

  async function normalise(input, decoyCache) {
    const now = Date.now();
    let decoy;
    if (decoyCache && input.decoy) decoy = decoyCache.get(String(input.decoy));
    else if (input.decoy_id)
      decoy = await db.get("SELECT * FROM decoys WHERE id = ?", input.decoy_id);
    else
      decoy = await db.get(
        "SELECT * FROM decoys WHERE name = ?",
        String(input.decoy || ""),
      );
    if (!decoy) throw bad("Unknown decoy");
    if (!decoy.enabled && !input.allowPaused)
      throw new HttpError(409, "Decoy is disabled");
    if (!isIp(input.src_ip))
      throw bad("src_ip must be a valid IPv4/IPv6 address");
    const typeKey = String(input.type_key || "");
    if (!/^[a-z0-9_.]{3,40}$/.test(typeKey))
      throw bad("type_key must match [a-z0-9_.]{3,40}");
    const known = EVENT_TYPES[typeKey];
    const ts = input.ts === undefined ? now : Number(input.ts);
    if (!Number.isFinite(ts) || ts > now + 5 * 60e3 || ts < now - 400 * 86400e3)
      throw bad("ts out of range");
    const int = (v, d, lo, hi, name) => {
      if (v === undefined || v === null) return d;
      const n = Math.trunc(Number(v));
      if (!Number.isFinite(n) || n < lo || n > hi)
        throw bad(`${name} out of range`);
      return n;
    };
    const attempts = int(input.attempts, 1, 1, 1e6, "attempts");
    const distinct_n = int(input.distinct_n, 0, 0, 1e6, "distinct_n");
    const duration_s = int(input.duration_s, 0, 0, 86400, "duration_s");
    const severity = input.severity
      ? String(input.severity).toLowerCase()
      : severityFor(typeKey, attempts);
    if (!SEVERITIES.includes(severity)) throw bad("invalid severity");
    let summary = input.summary ? String(input.summary).slice(0, 120) : "";
    if (!summary) {
      if (!known) throw bad("summary is required for custom type_key");
      summary = known.showAttempts
        ? `${known.label} · ${attempts} attempts`
        : known.label;
    }
    return {
      ts: Math.trunc(ts),
      severity,
      decoy,
      src_ip: input.src_ip,
      country: /^[A-Z]{2}$/.test(input.country || "") ? input.country : "??",
      protocol: decoy.protocol,
      type_key: typeKey,
      category: known ? known.category : "other",
      summary,
      attempts,
      distinct_n,
      duration_s,
      payload: String(input.payload || "").slice(0, 2000),
      simulated: input.simulated === false ? 0 : 1,
    };
  }

  async function createAlert({
    rule,
    event,
    decoy,
    title,
    severity,
    manual = 0,
    owner = null,
  }) {
    const ord = (decoy.name.match(/(\d+)$/) || [null, "01"])[1].padStart(
      2,
      "0",
    );
    const code = manual ? `MANUAL-${event.id}` : `${rule.code}-${ord}`;
    const r = await db.get(
      `INSERT INTO alerts(code,title,severity,status,owner_id,rule_id,decoy_id,event_id,src_ip,created_at,manual)
      VALUES(?,?,?,?,?,?,?,?,?,?,?) RETURNING id`,
      code,
      title,
      severity,
      "open",
      owner,
      rule ? rule.id : null,
      decoy.id,
      event.id,
      event.src_ip,
      event.ts,
      manual,
    );
    return { id: r.id, code, title, severity };
  }

  async function afterAlert(alert, rule, event, silent, opts) {
    await db.run(
      "INSERT INTO notifications(ts,severity,text,link) VALUES(?,?,?,?)",
      event.ts,
      alert.severity,
      `${alert.title} (${alert.code})`,
      "#/alerts",
    );
    const autoBlock =
      opts.autoBlock !== undefined && opts.autoBlock !== null
        ? opts.autoBlock
        : (await getSetting(db, "auto_block", "0")) === "1";
    if (autoBlock) {
      const n = (
        await db.get(
          "SELECT COUNT(*) AS c FROM alerts WHERE src_ip = ? AND created_at > ?",
          event.src_ip,
          event.ts - 86400e3,
        )
      ).c;
      if (n >= 3) {
        const ins = await db.run(
          `INSERT INTO blocked_ips(ip,reason,created_by,created_at) VALUES(?,?,?,?) ON CONFLICT (ip) DO NOTHING`,
          event.src_ip,
          "auto: repeat offender (3+ alerts in 24h)",
          "system",
          event.ts,
        );
        if (ins.changes)
          await audit(db, {
            user: "system",
            action: "Auto-blocked IP",
            target: event.src_ip,
            ts: event.ts,
          });
      }
    }
    if (
      !silent &&
      rule &&
      /email/i.test(rule.notify) &&
      (await getSetting(db, "email_notifications", "1")) === "1"
    ) {
      const to = (
        await db.all(
          "SELECT email FROM users WHERE active = 1 AND email <> '' AND role IN ('admin','analyst')",
        )
      ).map((u) => u.email);
      notifier
        .sendEmail(
          to,
          `[Honeypot Atlas] ${alert.severity.toUpperCase()}: ${alert.title}`,
          `${alert.title}\nCode: ${alert.code}\nSource: ${event.src_ip}\nSimulated telemetry: ${event.simulated ? "yes" : "no"}`,
        )
        .catch(() => {});
    }
  }

  /** The one pipeline every event goes through: validate -> store -> evaluate rules -> alerts. */
  async function ingest(input, opts = {}) {
    const { silent = false } = opts;
    const t0 = performance.now();
    const e = await normalise(input, opts.decoys);
    const result = await db.tx(async () => {
      const rules = (await loadRules()).get(e.type_key) || [];
      const row = await db.get(
        `INSERT INTO events(ts,severity,decoy_id,src_ip,country,protocol,type_key,category,summary,attempts,distinct_n,duration_s,payload,detected,simulated)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`,
        e.ts,
        e.severity,
        e.decoy.id,
        e.src_ip,
        e.country,
        e.protocol,
        e.type_key,
        e.category,
        e.summary,
        e.attempts,
        e.distinct_n,
        e.duration_s,
        e.payload,
        rules.length ? 1 : 0,
        e.simulated,
      );
      const event = {
        id: row.id,
        ts: e.ts,
        severity: e.severity,
        src_ip: e.src_ip,
        simulated: e.simulated,
        summary: e.summary,
      };
      const alerts = [];
      for (const rule of rules) {
        let ev;
        try {
          ev = await evaluate(rule, e.src_ip, e.ts);
        } catch (err) {
          metrics.lastRuleError = err.message;
          metrics.lastRuleErrorAt = Date.now();
          throw err;
        }
        if (!ev.passes) continue;
        await db.run(
          "INSERT INTO rule_hits(rule_id,event_id,src_ip,ts) VALUES(?,?,?,?)",
          rule.id,
          event.id,
          e.src_ip,
          e.ts,
        );
        // serialise concurrent events for the same rule+decoy so only one alert is created per cooldown window
        await db.run(
          "SELECT pg_advisory_xact_lock(?::bigint)",
          rule.id * 1000000 + e.decoy.id,
        );
        const recent = await db.get(
          "SELECT 1 AS x FROM alerts WHERE rule_id = ? AND decoy_id = ? AND created_at > ? LIMIT 1",
          rule.id,
          e.decoy.id,
          e.ts - ALERT_COOLDOWN_MS,
        );
        if (recent) continue;
        const known = EVENT_TYPES[e.type_key];
        const title =
          known && known.alertTitle
            ? known.alertTitle(e.decoy.name)
            : `${rule.name} on ${e.decoy.name}`;
        const a = await createAlert({
          rule,
          event,
          decoy: e.decoy,
          title,
          severity: rule.severity,
        });
        await afterAlert(a, rule, event, silent, opts);
        alerts.push(a);
      }
      return { event: { ...event, decoy: e.decoy.name }, alerts };
    });
    const ms = performance.now() - t0;
    metrics.ingestSamples += 1;
    metrics.ingestAvgMs =
      metrics.ingestSamples === 1 ? ms : metrics.ingestAvgMs * 0.95 + ms * 0.05;
    metrics.lastIngestAt = Date.now();
    if (!silent)
      bus.emit("change", { kind: result.alerts.length ? "alert" : "event" });
    return result;
  }

  async function createManualAlert(eventId, user) {
    const event = await db.get("SELECT * FROM events WHERE id = ?", eventId);
    if (!event) throw new HttpError(404, "Event not found");
    const existing = await db.get(
      "SELECT id, code FROM alerts WHERE event_id = ? AND manual = 1",
      eventId,
    );
    if (existing)
      throw new HttpError(
        409,
        `An alert already exists for this event (${existing.code})`,
      );
    const decoy = await db.get(
      "SELECT * FROM decoys WHERE id = ?",
      event.decoy_id,
    );
    const alert = await db.tx(async () => {
      const a = await createAlert({
        rule: null,
        event,
        decoy,
        title: `${event.summary} on ${decoy.name}`,
        severity: event.severity,
        manual: 1,
        owner: user.id,
      });
      await db.run(
        "INSERT INTO notifications(ts,severity,text,link) VALUES(?,?,?,?)",
        Date.now(),
        a.severity,
        `${a.title} (${a.code})`,
        "#/alerts",
      );
      return a;
    });
    bus.emit("change", { kind: "alert" });
    return alert;
  }

  /** Dry-run a rule over recent events without writing anything. */
  async function dryRun(rule, sinceTs = Date.now() - 86400e3) {
    const events = await db.all(
      "SELECT id, ts, src_ip, decoy_id FROM events WHERE type_key = ? AND ts > ? ORDER BY ts LIMIT 20000",
      rule.match_type,
      sinceTs,
    );
    const lastAlert = new Map();
    let hits = 0,
      alerts = 0;
    const sources = new Set();
    for (const ev of events) {
      if (!(await evaluate(rule, ev.src_ip, ev.ts)).passes) continue;
      hits += 1;
      sources.add(ev.src_ip);
      const last = lastAlert.get(ev.decoy_id);
      if (last === undefined || ev.ts - last > ALERT_COOLDOWN_MS) {
        alerts += 1;
        lastAlert.set(ev.decoy_id, ev.ts);
      }
    }
    return { scanned: events.length, hits, alerts, sources: sources.size };
  }

  return {
    bus,
    metrics,
    ingest,
    evaluate,
    dryRun,
    createManualAlert,
    invalidateRules,
    createAlert,
  };
}
