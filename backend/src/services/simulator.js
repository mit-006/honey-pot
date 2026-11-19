// Synthetic honeypot traffic. SAFETY: this module only fabricates records and feeds them to the engine.
// It opens no sockets, performs no scanning and only uses RFC 5737 / RFC 3849 documentation addresses.
import { COUNTRIES, EVENT_TYPES } from "../catalog.js";

export function makeRng(seed = 1) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  next.int = (lo, hi) => lo + Math.floor(next() * (hi - lo + 1));
  next.pick = (arr) => arr[Math.floor(next() * arr.length)];
  next.chance = (p) => next() < p;
  return next;
}

const COUNTRY_WEIGHTS = [
  ["DE", 20],
  ["NL", 14],
  ["CN", 11],
  ["US", 9],
  ["RU", 8],
  ["BR", 6],
  ["IN", 6],
  ["VN", 5],
  ["KR", 4],
  ["FR", 4],
  ["GB", 4],
  ["ID", 3],
];
export const SIM_COUNTRY_CODES = Object.keys(COUNTRIES);

export function buildAttackerPool(rng, size = 1400) {
  const total = COUNTRY_WEIGHTS.reduce((s, [, w]) => s + w, 0);
  const pickCountry = () => {
    let r = rng() * total;
    for (const [c, w] of COUNTRY_WEIGHTS) {
      r -= w;
      if (r <= 0) return c;
    }
    return "DE";
  };
  const seen = new Set();
  const pool = [];
  const v4 = ["192.0.2", "198.51.100", "203.0.113"];
  let v4n = 0;
  while (pool.length < size) {
    let ip;
    if (rng() < 0.8 && v4n < 700) ip = `${rng.pick(v4)}.${rng.int(1, 254)}`;
    else
      ip = `2001:db8:${rng.int(0x1000, 0xffff).toString(16)}::${rng.int(1, 0xfff).toString(16)}`;
    if (seen.has(ip)) continue;
    seen.add(ip);
    if (!ip.includes(":")) v4n++;
    pool.push({ ip, country: pickCountry() });
  }
  return pool;
}

const CREDS = [
  "root / admin123",
  "admin / password",
  "ubuntu / ubuntu1",
  "test / test123",
  "oracle / oracle",
  "pi / raspberry",
  "user / 123456",
  "postgres / postgres",
  "git / git",
  "ftpuser / ftpuser",
];
const SQLI = [
  "GET /admin/login.php?id=1' OR '1'='1' --",
  "GET /products?cat=1 UNION SELECT NULL,NULL--",
  "POST /search q=' OR 1=1;--",
  "GET /item?id=1; WAITFOR DELAY '0:0:5'--",
];
const LFI = [
  "GET /download?file=../../../../etc/passwd",
  "GET /static/..%2f..%2f..%2fetc/hosts",
  "GET /view?page=....//....//windows/win.ini",
];

function payloadFor(type, rng, e) {
  switch (type) {
    case "ssh.brute_force":
      return Array.from({ length: 3 }, () => rng.pick(CREDS)).join("\n");
    case "http.sqli":
      return rng.pick(SQLI);
    case "http.webshell":
      return 'POST /upload.php\nContent-Disposition: form-data; name="file"; filename="shell.php"\n(content discarded by decoy)';
    case "http.lfi":
      return rng.pick(LFI);
    case "mysql.cred_stuffing":
      return Array.from({ length: 3 }, () => rng.pick(CREDS)).join("\n");
    case "smb.enum":
      return `tree_connect \\\\${e.host}\\IPC$\ntree_connect \\\\${e.host}\\ADMIN$\ntree_connect \\\\${e.host}\\Backups`;
    case "rdp.nla":
      return "negotiate: requestedProtocols=PROTOCOL_RDP (NLA not requested)";
    case "redis.info":
      return "INFO";
    case "redis.config":
      return "CONFIG GET dir";
    case "ftp.anon":
      return "USER anonymous\nPASS guest@example.test";
    case "dns.axfr":
      return "AXFR corp.example.test";
    case "net.portscan":
      return `SYN sweep across ${e.distinct_n} ports`;
    default:
      return "";
  }
}

function shape(type, rng) {
  switch (type) {
    case "ssh.brute_force": {
      const r = rng();
      const attempts =
        r < 0.7
          ? rng.int(3, 25)
          : r < 0.9
            ? rng.int(26, 90)
            : r < 0.98
              ? rng.int(91, 250)
              : rng.int(251, 600);
      return {
        attempts,
        distinct_n: Math.min(attempts, rng.int(3, 12)),
        duration_s: Math.max(1, Math.round(attempts * (0.15 + rng() * 0.35))),
      };
    }
    case "http.sqli":
      return {
        attempts: rng.int(1, 4),
        distinct_n: 0,
        duration_s: rng.int(1, 30),
      };
    case "http.webshell":
      return { attempts: 1, distinct_n: 0, duration_s: 1 };
    case "http.lfi":
      return {
        attempts: rng.int(1, 3),
        distinct_n: 0,
        duration_s: rng.int(1, 10),
      };
    case "mysql.cred_stuffing":
      return {
        attempts: rng.int(5, 80),
        distinct_n: rng.int(2, 18),
        duration_s: rng.int(10, 120),
      };
    case "smb.enum":
      return {
        attempts: rng.int(1, 5),
        distinct_n: rng.int(1, 4),
        duration_s: rng.int(1, 40),
      };
    case "net.portscan": {
      const n = rng.int(8, 400);
      return { attempts: n, distinct_n: n, duration_s: rng.int(2, 60) };
    }
    default:
      return { attempts: 1, distinct_n: 0, duration_s: rng.int(0, 3) };
  }
}

// Types that tend to arrive as short campaigns from the same source
const BURSTY = {
  "ssh.brute_force": 0.35,
  "http.sqli": 0.45,
  "smb.enum": 0.35,
  "mysql.cred_stuffing": 0.3,
  "http.lfi": 0.2,
};

export function createGenerator({ rng, pool }) {
  const types = Object.entries(EVENT_TYPES);
  const poolPick = () =>
    pool[
      Math.min(pool.length - 1, Math.floor(pool.length * Math.pow(rng(), 2.3)))
    ];

  /** @returns ingest inputs for one "arrival" (1 event, sometimes a short campaign of several). */
  function arrival({ decoys, ts, typeKey }) {
    const live = decoys.filter((d) => d.enabled);
    if (!live.length) return [];
    const avail = types.filter(
      ([, t]) =>
        t.protocol === null || live.some((d) => d.protocol === t.protocol),
    );
    let key = typeKey;
    if (!key) {
      const total = avail.reduce((s, [, t]) => s + t.weight, 0);
      let r = rng() * total;
      key = avail[avail.length - 1][0];
      for (const [k, t] of avail) {
        r -= t.weight;
        if (r <= 0) {
          key = k;
          break;
        }
      }
    }
    const t = EVENT_TYPES[key];
    const candidates = t.protocol
      ? live.filter((d) => d.protocol === t.protocol)
      : live;
    const decoy =
      candidates[
        Math.min(
          candidates.length - 1,
          Math.floor(candidates.length * Math.pow(rng(), 1.4)),
        )
      ];
    const attacker = poolPick();
    const out = [];
    const count = rng.chance(BURSTY[key] || 0) ? rng.int(2, 7) : 1;
    let at = ts;
    for (let i = 0; i < count; i++) {
      const s = shape(key, rng);
      const e = { host: decoy.host, distinct_n: s.distinct_n };
      out.push({
        ts: Math.round(at),
        decoy: decoy.name,
        src_ip: attacker.ip,
        country: attacker.country,
        type_key: key,
        attempts: s.attempts,
        distinct_n: s.distinct_n,
        duration_s: s.duration_s,
        payload: payloadFor(key, rng, e),
        simulated: true,
      });
      at += rng.int(20, 240) * 1000;
    }
    return out;
  }
  return { arrival };
}

// 0..1 multiplier for time-of-day / weekday traffic shape (UTC)
export function activityFactor(ts) {
  const d = new Date(ts);
  const h = d.getUTCHours() + d.getUTCMinutes() / 60;
  const daily = 0.72 + 0.38 * Math.sin(((h - 8) / 24) * Math.PI * 2);
  const weekday = [0.82, 1.05, 1.08, 1.05, 1.0, 0.95, 0.85][d.getUTCDay()];
  return Math.max(0.25, daily * weekday);
}

export function startSimulator({ engine, db, config, logger = console }) {
  const rng = makeRng((Date.now() & 0xffff) + 7);
  const gen = createGenerator({
    rng,
    pool: buildAttackerPool(makeRng(20261025)),
  });
  let running = false;
  const tick = async () => {
    if (running) return; // never overlap ticks if the database is slow
    running = true;
    try {
      const decoys = await db.all("SELECT * FROM decoys WHERE enabled = 1");
      const lambda =
        2.2 * activityFactor(Date.now()) * (config.simulatorIntervalMs / 4000);
      let n = 0;
      for (let i = 0; i < 6; i++) if (rng() < lambda / 6) n++;
      if (!n && rng() < 0.5) n = 1;
      const batch = [];
      const now = Date.now();
      for (let i = 0; i < n; i++)
        batch.push(...gen.arrival({ decoys, ts: now - rng.int(0, 2500) }));
      batch.sort((a, b) => a.ts - b.ts);
      for (const e of batch) {
        e.ts = Math.min(e.ts, now);
        try {
          await engine.ingest(e);
        } catch (err) {
          logger.warn("[simulator] skipped event:", err.message);
        }
      }
    } catch (err) {
      logger.warn("[simulator] tick failed:", err.message);
    } finally {
      running = false;
    }
  };
  const timer = setInterval(tick, config.simulatorIntervalMs);
  timer.unref();
  return { stop: () => clearInterval(timer), tick, generator: gen };
}

/** Emit n synthetic arrivals right now (admin demo endpoint and tests). */
export async function simulateBurst({ engine, db, n = 5, typeKey, seed }) {
  const rng = makeRng(seed ?? Date.now() & 0xffff);
  const gen = createGenerator({
    rng,
    pool: buildAttackerPool(makeRng(20261025)),
  });
  const decoys = await db.all("SELECT * FROM decoys WHERE enabled = 1");
  const out = [];
  const now = Date.now();
  for (let i = 0; i < n; i++)
    for (const e of gen.arrival({ decoys, ts: now - (n - i) * 1500, typeKey }))
      out.push(e);
  out.sort((a, b) => a.ts - b.ts);
  let created = 0,
    alerts = 0;
  for (const e of out) {
    e.ts = Math.min(e.ts, Date.now());
    const r = await engine.ingest(e);
    created++;
    alerts += r.alerts.length;
  }
  return { events: created, alerts };
}
