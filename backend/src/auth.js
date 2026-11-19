import crypto from "node:crypto";
import { HttpError } from "./util.js";

const COOKIE = "atlas_session";
const ROLE_RANK = { viewer: 1, analyst: 2, admin: 3 };

export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt.toString("hex")}$${hash.toString("hex")}`;
}
export function verifyPassword(password, stored) {
  const [scheme, saltHex, hashHex] = String(stored).split("$");
  if (scheme !== "scrypt" || !saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, "hex");
  const actual = crypto.scryptSync(
    password,
    Buffer.from(saltHex, "hex"),
    expected.length,
  );
  return crypto.timingSafeEqual(expected, actual);
}
export const sha256 = (s) =>
  crypto.createHash("sha256").update(s).digest("hex");
export const randomToken = (bytes = 32) =>
  crypto.randomBytes(bytes).toString("base64url");
export const tempPassword = () => `${randomToken(6)}-${randomToken(6)}`;
export const safeEqual = (a, b) => {
  const x = Buffer.from(a),
    y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

export function parseCookies(header = "") {
  const out = {};
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0)
      out[part.slice(0, i).trim()] = decodeURIComponent(
        part.slice(i + 1).trim(),
      );
  }
  return out;
}

export function createAuth({ db, config }) {
  const failures = new Map();
  const WINDOW = 10 * 60 * 1000,
    MAX_FAILS = 8;

  function throttled(key) {
    const f = failures.get(key);
    if (!f) return false;
    if (Date.now() - f.first > WINDOW) {
      failures.delete(key);
      return false;
    }
    return f.count >= MAX_FAILS;
  }
  function noteFailure(key) {
    const f = failures.get(key);
    if (!f || Date.now() - f.first > WINDOW)
      failures.set(key, { count: 1, first: Date.now() });
    else f.count += 1;
  }

  async function createSession(userId) {
    const token = randomToken();
    const now = Date.now();
    await db.run(
      "INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
      sha256(token),
      userId,
      now,
      now + config.sessionTtlMs,
    );
    return token;
  }
  const cookieHeader = (token, maxAgeMs) => {
    const parts = [
      `${COOKIE}=${encodeURIComponent(token)}`,
      "Path=/",
      "HttpOnly",
      "SameSite=Strict",
      `Max-Age=${Math.floor(maxAgeMs / 1000)}`,
    ];
    if (config.cookieSecure) parts.push("Secure");
    return parts.join("; ");
  };

  async function login(username, password, ip) {
    const key = `${ip}|${String(username).toLowerCase()}`;
    if (throttled(key))
      throw new HttpError(
        429,
        "Too many failed attempts. Try again in a few minutes.",
      );
    const user = await db.get(
      "SELECT * FROM users WHERE lower(username) = lower(?)",
      String(username || ""),
    );
    const ok = user
      ? verifyPassword(String(password || ""), user.password_hash)
      : (verifyPassword("x", "scrypt$00$00"), false);
    if (!user || !ok || !user.active) {
      noteFailure(key);
      throw new HttpError(401, "Invalid username or password.");
    }
    failures.delete(key);
    return { user, token: await createSession(user.id) };
  }
  const logout = async (token) => {
    if (token)
      await db.run("DELETE FROM sessions WHERE token_hash = ?", sha256(token));
  };

  async function userFromToken(token) {
    if (!token) return null;
    const row = await db.get(
      `SELECT u.id, u.username, u.name, u.email, u.role, u.active, u.must_change, s.expires_at
      FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`,
      sha256(token),
    );
    return !row || row.expires_at < Date.now() || !row.active ? null : row;
  }

  async function attach(req, _res, next) {
    req.sessionToken = parseCookies(req.headers.cookie)[COOKIE];
    req.user = await userFromToken(req.sessionToken);
    next();
  }

  /** Mutations need the custom header (cross-site forms/fetches cannot set it) and a same-origin Origin. */
  function csrf(req, _res, next) {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
    if (req.path === "/ingest" || req.path.startsWith("/ingest/"))
      return next(); // API-key auth, no cookies
    if (req.headers["x-atlas-csrf"] !== "1")
      return next(new HttpError(403, "Missing CSRF header"));
    const origin = req.headers.origin;
    if (origin) {
      try {
        if (new URL(origin).host !== req.headers.host)
          return next(new HttpError(403, "Cross-origin request blocked"));
      } catch {
        return next(new HttpError(403, "Bad origin"));
      }
    }
    next();
  }

  const requireAuth = (req, _res, next) =>
    req.user ? next() : next(new HttpError(401, "Authentication required"));
  const requireRole = (role) => (req, _res, next) => {
    if (!req.user) return next(new HttpError(401, "Authentication required"));
    if (ROLE_RANK[req.user.role] < ROLE_RANK[role])
      return next(new HttpError(403, `Requires ${role} role`));
    next();
  };

  return {
    login,
    logout,
    attach,
    csrf,
    requireAuth,
    requireRole,
    cookieHeader,
    cookieName: COOKIE,
    purgeSessions: () =>
      db.run("DELETE FROM sessions WHERE expires_at < ?", Date.now()),
  };
}
