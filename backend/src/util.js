export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

const RANGES = { '1h': 3600e3, '24h': 24 * 3600e3, '7d': 7 * 24 * 3600e3, '30d': 30 * 24 * 3600e3 };
export function parseRange(v, fallback = '24h') {
  const key = RANGES[v] ? v : fallback;
  return { key, ms: RANGES[key] };
}

export function intParam(v, d, min = 0, max = 1e9) {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : d;
}

export function csvCell(v) {
  let s = v === null || v === undefined ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // neutralise spreadsheet formula injection
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
export const csvRow = (cells) => cells.map(csvCell).join(',') + '\n';

export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
export const bad = (msg) => new HttpError(400, msg);

/** Client IP as seen through the trusted reverse proxy (Express "trust proxy" setting). */
export const clientIp = (req) => String(req.ip || (req.socket && req.socket.remoteAddress) || '').replace(/^::ffff:/, '');

export const oneOf = (v, list, name) => {
  if (!list.includes(v)) throw bad(`${name} must be one of: ${list.join(', ')}`);
  return v;
};
export const str = (v, name, { min = 1, max = 200 } = {}) => {
  if (typeof v !== 'string') throw bad(`${name} is required`);
  const s = v.trim();
  if (s.length < min || s.length > max) throw bad(`${name} must be ${min}-${max} characters`);
  return s;
};
export function isIp(v) {
  if (typeof v !== 'string') return false;
  if (/^(\d{1,3})(\.\d{1,3}){3}$/.test(v)) return v.split('.').every((o) => Number(o) <= 255);
  return /^[0-9a-fA-F:]{2,39}$/.test(v) && v.includes(':');
}
