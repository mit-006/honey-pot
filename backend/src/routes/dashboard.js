import express from "express";
import { CATEGORIES, COUNTRIES } from "../catalog.js";
import { intParam, parseRange } from "../util.js";

const bucketCount = { "1h": 12, "24h": 24, "7d": 28, "30d": 30 };
const pct = (cur, prev) => (prev > 0 ? ((cur - prev) / prev) * 100 : null);

export function dashboardRouter({ db, engine }) {
  const r = express.Router();

  async function series(
    from,
    to,
    n,
    agg = "COUNT(*)",
    where = "1=1",
    params = [],
  ) {
    const size = (to - from) / n;
    const out = new Array(n).fill(0);
    const rows = await db.all(
      `SELECT FLOOR((ts - ?::bigint)::float8 / ?::float8)::int AS b, ${agg} AS v FROM events
      WHERE ts > ? AND ts <= ? AND ${where} GROUP BY b`,
      Math.round(from),
      size,
      Math.round(from),
      Math.round(to),
      ...params,
    );
    for (const x of rows) out[Math.min(n - 1, Math.max(0, x.b))] = x.v;
    return { values: out, size };
  }
  const openAt = async (t) =>
    (
      await db.get(
        `SELECT COUNT(*) AS c FROM alerts WHERE created_at <= ?
    AND (acknowledged_at IS NULL OR acknowledged_at > ?) AND (resolved_at IS NULL OR resolved_at > ?)`,
        Math.round(t),
        Math.round(t),
        Math.round(t),
      )
    ).c;

  r.get("/overview", async (req, res) => {
    const now = Date.now();
    const { ms, key } = parseRange(req.query.range, "24h");
    const from = now - ms,
      pfrom = from - ms;
    const n = bucketCount[key];
    const cnt = async (a, b, where = "1=1") =>
      (
        await db.get(
          `SELECT COUNT(*) AS c FROM events WHERE ts > ? AND ts <= ? AND ${where}`,
          a,
          b,
        )
      ).c;
    const uniq = async (a, b) =>
      (
        await db.get(
          "SELECT COUNT(DISTINCT src_ip) AS c FROM events WHERE ts > ? AND ts <= ?",
          a,
          b,
        )
      ).c;

    const [
      events,
      prevEvents,
      attackers,
      prevAttackers,
      critical,
      prevCritical,
    ] = await Promise.all([
      cnt(from, now),
      cnt(pfrom, from),
      uniq(from, now),
      uniq(pfrom, from),
      cnt(from, now, "severity = 'critical'"),
      cnt(pfrom, from, "severity = 'critical'"),
    ]);
    const open = (
      await db.get("SELECT COUNT(*) AS c FROM alerts WHERE status = 'open'")
    ).c;
    const openStart = await openAt(from);
    const openSpark = await Promise.all(
      Array.from({ length: 8 }, (_, i) => openAt(from + ((i + 1) / 8) * ms)),
    );
    const decoys = await db.all("SELECT enabled, health FROM decoys");
    const online = decoys.filter(
      (d) => d.enabled && d.health === "online",
    ).length;

    const trend = await series(from, now, n);
    const peakIdx = trend.values.indexOf(Math.max(...trend.values));
    const [spark24, attackerSpark, critSpark, decoySpark] = await Promise.all([
      series(from, now, 24),
      series(from, now, 8, "COUNT(DISTINCT src_ip)"),
      series(from, now, 8, "COUNT(*)", "severity = 'critical'"),
      series(from, now, 8, "COUNT(DISTINCT decoy_id)"),
    ]);

    const sev = Object.fromEntries(
      (
        await db.all(
          "SELECT severity AS s, COUNT(*) AS c FROM events WHERE ts > ? GROUP BY severity",
          from,
        )
      ).map((x) => [x.s, x.c]),
    );
    const countries = (
      await db.all(
        "SELECT country AS c, COUNT(*) AS n FROM events WHERE ts > ? GROUP BY country ORDER BY n DESC LIMIT 4",
        from,
      )
    ).map((x) => ({ code: x.c, name: COUNTRIES[x.c] || x.c, count: x.n }));
    const recent = await db.all(
      "SELECT e.id, e.ts, e.severity, d.name AS decoy, e.src_ip, e.summary FROM events e JOIN decoys d ON d.id = e.decoy_id ORDER BY e.ts DESC, e.id DESC LIMIT 7",
    );

    // system health: measured, not hard-coded
    const t0 = performance.now();
    await db.get("SELECT COUNT(*) AS c FROM decoys");
    const dbMs = Math.max(1, Math.round(performance.now() - t0));
    const m = engine.metrics;
    const recentIngest = Date.now() - m.lastIngestAt < 5 * 60e3;
    const ruleErr =
      m.lastRuleError && Date.now() - m.lastRuleErrorAt < 10 * 60e3;
    const health = [
      {
        name: "Sensor gateway",
        state: recentIngest ? "ok" : "warn",
        text: recentIngest
          ? `${Math.max(1, Math.round(m.ingestAvgMs / 2))} ms`
          : "idle",
      },
      {
        name: "Ingest pipeline",
        state: recentIngest ? "ok" : "warn",
        text: recentIngest
          ? `${Math.max(1, Math.round(m.ingestAvgMs))} ms`
          : "idle",
      },
      {
        name: "Rule engine",
        state: ruleErr ? "warn" : "ok",
        text: ruleErr ? "degraded" : "ok",
      },
      {
        name: "Database",
        state: dbMs > 200 ? "warn" : "ok",
        text: `${dbMs} ms`,
      },
    ];

    res.json({
      now,
      range: key,
      bucketMs: trend.size,
      from,
      kpis: {
        events: {
          value: events,
          delta: pct(events, prevEvents),
          spark: spark24.values,
        },
        attackers: {
          value: attackers,
          delta: pct(attackers, prevAttackers),
          spark: attackerSpark.values,
        },
        openAlerts: { value: open, change: open - openStart, spark: openSpark },
        critical: {
          value: critical,
          delta: pct(critical, prevCritical),
          spark: critSpark.values,
        },
        decoys: {
          online,
          total: decoys.length,
          attention: decoys.length - online,
          spark: decoySpark.values,
        },
      },
      trend: {
        values: trend.values,
        peakIndex: peakIdx,
        peakTs: from + (peakIdx + 0.5) * trend.size,
        peakPerMin: trend.values[peakIdx] / (trend.size / 60000),
      },
      severity: sev,
      countries,
      recent,
      health,
    });
  });

  r.get("/analytics", async (req, res) => {
    const now = Date.now();
    const { ms, key } = parseRange(req.query.range, "24h");
    const from = now - ms,
      pfrom = from - ms;
    const n = bucketCount[key];
    const tz = intParam(req.query.tz, 0, -840, 840);
    const total = (a, b) =>
      db.get(
        "SELECT COUNT(*) AS c, COUNT(DISTINCT src_ip) AS u, COALESCE(SUM(detected),0) AS d FROM events WHERE ts > ? AND ts <= ?",
        a,
        b,
      );
    const [cur, prev] = await Promise.all([
      total(from, now),
      total(pfrom, from),
    ]);
    const mtta = async (a, b) =>
      (
        await db.get(
          "SELECT AVG(acknowledged_at - created_at) AS v FROM alerts WHERE created_at > ? AND created_at <= ? AND acknowledged_at IS NOT NULL",
          a,
          b,
        )
      ).v;
    const [curMtta, prevMtta] = [
      await mtta(from, now),
      await mtta(pfrom, from),
    ];
    const rate = cur.c ? (cur.d / cur.c) * 100 : null,
      prevRate = prev.c ? (prev.d / prev.c) * 100 : null;

    const ev = await series(from, now, n),
      at = await series(from, now, n, "COUNT(DISTINCT src_ip)");
    const spark24 = await series(from, now, 24),
      spark8 = await series(from, now, 8, "COUNT(DISTINCT src_ip)");
    const protoRows = await db.all(
      "SELECT protocol AS p, COUNT(*) AS c FROM events WHERE ts > ? GROUP BY protocol ORDER BY c DESC",
      from,
    );
    const top = protoRows.slice(0, 4),
      other = protoRows.slice(4).reduce((s, x) => s + x.c, 0);
    const protocols = [
      ...top.map((x) => ({ name: x.p, count: x.c })),
      ...(other ? [{ name: "Other", count: other }] : []),
    ];
    const types = (
      await db.all(
        "SELECT category AS c, COUNT(*) AS n FROM events WHERE ts > ? GROUP BY category ORDER BY n DESC LIMIT 5",
        from,
      )
    ).map((x) => ({ name: CATEGORIES[x.c] || x.c, count: x.n }));

    // activity heatmap: last 30 days, local hour x weekday (Mon..Sun)
    const heat = Array.from({ length: 7 }, () => new Array(24).fill(0));
    const rows = await db.all(
      `SELECT EXTRACT(DOW FROM to_timestamp(ts / 1000.0 + ?::float8) AT TIME ZONE 'UTC')::int AS dow,
        EXTRACT(HOUR FROM to_timestamp(ts / 1000.0 + ?::float8) AT TIME ZONE 'UTC')::int AS hr, COUNT(*) AS c
      FROM events WHERE ts > ? GROUP BY 1, 2`,
      tz * 60,
      tz * 60,
      now - 30 * 86400e3,
    );
    for (const x of rows) heat[(x.dow + 6) % 7][x.hr] = x.c;

    res.json({
      range: key,
      now,
      from,
      bucketMs: ev.size,
      kpis: {
        events: {
          value: cur.c,
          delta: pct(cur.c, prev.c),
          spark: spark24.values,
        },
        attackers: {
          value: cur.u,
          delta: pct(cur.u, prev.u),
          spark: spark8.values,
        },
        mtta: {
          valueMs: curMtta,
          deltaMs:
            curMtta !== null && prevMtta !== null ? curMtta - prevMtta : null,
          spark: [],
        },
        detection: {
          value: rate,
          deltaPts: rate !== null && prevRate !== null ? rate - prevRate : null,
        },
      },
      trend: { events: ev.values, attackers: at.values },
      protocols,
      types,
      heatmap: heat,
    });
  });
  return r;
}
