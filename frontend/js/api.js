export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export async function api(method, path, body) {
  let res;
  try {
    res = await fetch("/api" + path, {
      method,
      credentials: "same-origin",
      headers: { "content-type": "application/json", "x-atlas-csrf": "1" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "Cannot reach the server");
  }
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* empty body */
  }
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith("/auth/login"))
      window.dispatchEvent(new CustomEvent("atlas:unauth"));
    throw new ApiError(
      res.status,
      (data && data.error) || `Request failed (${res.status})`,
    );
  }
  return data;
}
export const get = (p) => api("GET", p);
export const post = (p, b = {}) => api("POST", p, b);
export const patch = (p, b) => api("PATCH", p, b);
export const del = (p) => api("DELETE", p);

/** Build a query string, skipping empty values; Sets/arrays become comma lists. */
export function qs(obj) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) {
    const val = v instanceof Set || Array.isArray(v) ? [...v].join(",") : v;
    if (val !== undefined && val !== null && val !== "") p.set(k, val);
  }
  const s = p.toString();
  return s ? "?" + s : "";
}
