import express from "express";
import { audit } from "../db.js";
import {
  HttpError,
  SEVERITIES,
  clientIp,
  csvRow,
  intParam,
  parseRange,
} from "../util.js";

const list = (v, allowed) =>
  String(v || "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s && (!allowed || allowed.includes(s)))
    .slice(0, 30);

export function buildEventFilter(q, now = Date.now()) {
  const { ms, key } = parseRange(q.range, "24h");
  const where = ["e.ts > ?"];
  const params = [now - ms];
  const inList = (col, values) => {
    where.push(`${col} IN (${values.map(() => "?").join(",")})`);
    params.push(...values);
  };
  const sev = list(q.severity, SEVERITIES);
  if (sev.length) inList("e.severity", sev);
  const decoys = list(q.decoy);
  if (decoys.length) inList("d.name", decoys);
  const protos = list(q.protocol);
  if (protos.length) inList("e.protocol", protos);
  const text = String(q.q || "")
    .trim()
    .toLowerCase()
    .slice(0, 100);
  if (text) {
    where.push(
      "(strpos(lower(e.src_ip), ?) > 0 OR strpos(lower(d.name), ?) > 0 OR strpos(lower(e.payload), ?) > 0 OR strpos(lower(e.summary), ?) > 0)",
    );
    params.push(text, text, text, text);
  }
  const ids = list(q.ids).map(Number).filter(Number.isInteger).slice(0, 5000);
  if (ids.length) inList("e.id", ids);
  return { sql: where.join(" AND "), params, range: key };
}

const COLS =
  "e.id, e.ts, e.severity, d.name AS decoy, e.src_ip, e.country, e.protocol, e.summary, e.attempts, e.duration_s";

export function eventsRouter({ db, engine, auth }) {
  const r = express.Router();

  r.get("/", async (req, res) => {
    const f = buildEventFilter(req.query);
    const pageSize = intParam(req.query.pageSize, 12, 5, 100);
    const total = (
      await db.get(
        `SELECT COUNT(*) AS c FROM events e JOIN decoys d ON d.id = e.decoy_id WHERE ${f.sql}`,
        ...f.params,
      )
    ).c;
    const pages = Math.max(1, Math.ceil(total / pageSize));
    const page = Math.min(intParam(req.query.page, 1, 1, 1e6), pages);
    const rows = await db.all(
      `SELECT ${COLS} FROM events e JOIN decoys d ON d.id = e.decoy_id WHERE ${f.sql}
      ORDER BY e.ts DESC, e.id DESC LIMIT ? OFFSET ?`,
      ...f.params,
      pageSize,
      (page - 1) * pageSize,
    );
    res.json({
      total,
      page,
      pages,
      pageSize,
      rows,
      options: {
        decoys: (await db.all("SELECT name FROM decoys ORDER BY name")).map(
          (x) => x.name,
        ),
        protocols: (
          await db.all("SELECT DISTINCT protocol FROM decoys ORDER BY protocol")
        ).map((x) => x.protocol),
      },
    });
  });

  r.get("/export.csv", async (req, res) => {
    const f = buildEventFilter(req.query);
    const rows = await db.all(
      `SELECT ${COLS}, e.type_key, e.simulated FROM events e JOIN decoys d ON d.id = e.decoy_id
      WHERE ${f.sql} ORDER BY e.ts DESC LIMIT 50000`,
      ...f.params,
    );
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="atlas-events-${f.range}.csv"`,
    );
    res.write(
      csvRow([
        "id",
        "time_utc",
        "severity",
        "decoy",
        "source_ip",
        "country",
        "protocol",
        "activity",
        "attempts",
        "duration_s",
        "type",
        "simulated",
      ]),
    );
    for (const e of rows) {
      res.write(
        csvRow([
          `EVT-${e.id}`,
          new Date(e.ts).toISOString(),
          e.severity,
          e.decoy,
          e.src_ip,
          e.country,
          e.protocol,
          e.summary,
          e.attempts,
          e.duration_s,
          e.type_key,
          e.simulated ? "yes" : "no",
        ]),
      );
    }
    await audit(db, {
      user: req.user.username,
      action: "Exported events",
      target: `CSV · ${f.range}`,
      ip: clientIp(req),
    });
    res.end();
  });

  r.get("/:id", async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id)) throw new HttpError(404, "Event not found");
    const e = await db.get(
      "SELECT e.*, d.name AS decoy, d.port, d.host FROM events e JOIN decoys d ON d.id = e.decoy_id WHERE e.id = ?",
      id,
    );
    if (!e) throw new HttpError(404, "Event not found");
    const related = await db.all(
      `SELECT e.id, e.ts, e.severity, d.name AS decoy, e.summary FROM events e JOIN decoys d ON d.id = e.decoy_id
      WHERE e.src_ip = ? AND e.id <> ? ORDER BY e.ts DESC LIMIT 4`,
      e.src_ip,
      e.id,
    );
    const alert = await db.get(
      "SELECT id, code, status FROM alerts WHERE event_id = ? ORDER BY id LIMIT 1",
      e.id,
    );
    const sourceCount = (
      await db.get(
        "SELECT COUNT(*) AS c FROM events WHERE src_ip = ?",
        e.src_ip,
      )
    ).c;
    const blocked = Boolean(
      await db.get("SELECT 1 AS x FROM blocked_ips WHERE ip = ?", e.src_ip),
    );
    res.json({ ...e, blocked, related, alert: alert || null, sourceCount });
  });

  r.post("/:id/alert", auth.requireRole("analyst"), async (req, res) => {
    const a = await engine.createManualAlert(Number(req.params.id), req.user);
    await audit(db, {
      user: req.user.username,
      action: "Created alert",
      target: a.code,
      ip: clientIp(req),
    });
    res.status(201).json(a);
  });

  r.post("/:id/block-ip", auth.requireRole("analyst"), async (req, res) => {
    const e = await db.get(
      "SELECT src_ip FROM events WHERE id = ?",
      Number(req.params.id),
    );
    if (!e) throw new HttpError(404, "Event not found");
    const info = await db.run(
      "INSERT INTO blocked_ips(ip,reason,created_by,created_at) VALUES(?,?,?,?) ON CONFLICT (ip) DO NOTHING",
      e.src_ip,
      "manual block from event",
      req.user.username,
      Date.now(),
    );
    if (info.changes)
      await audit(db, {
        user: req.user.username,
        action: "Blocked IP",
        target: e.src_ip,
        ip: clientIp(req),
      });
    res.json({ blocked: true, ip: e.src_ip, already: !info.changes });
  });

  r.delete("/:id/block-ip", auth.requireRole("analyst"), async (req, res) => {
    const e = await db.get(
      "SELECT src_ip FROM events WHERE id = ?",
      Number(req.params.id),
    );
    if (!e) throw new HttpError(404, "Event not found");
    const info = await db.run("DELETE FROM blocked_ips WHERE ip = ?", e.src_ip);
    if (info.changes)
      await audit(db, {
        user: req.user.username,
        action: "Unblocked IP",
        target: e.src_ip,
        ip: clientIp(req),
      });
    res.json({ blocked: false, ip: e.src_ip });
  });

  return r;
}
