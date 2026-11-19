const ESC = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};
export const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
export const $ = (root, sel) => root.querySelector(sel);
export const $$ = (root, sel) => [...root.querySelectorAll(sel)];

const pad = (n) => String(n).padStart(2, "0");
const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];
const WEEK = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
export const hm = (ts) => {
  const d = new Date(ts);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
};
export const hms = (ts) => {
  const d = new Date(ts);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};
export const isToday = (ts) =>
  new Date(ts).toDateString() === new Date().toDateString();
export const dayLabel = (ts) => {
  const d = new Date(ts);
  return `${MONTHS[d.getMonth()]} ${d.getDate()}`;
};
export const fullTime = (ts) => {
  const d = new Date(ts);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${hms(ts)}`;
};
export const timeCell = (ts) =>
  isToday(ts) ? hms(ts) : `${dayLabel(ts)} ${hm(ts)}`;
export const longDate = (ts) => {
  const d = new Date(ts);
  return `${MONTHS[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`;
};
export const weekdayHour = (ts) => {
  const d = new Date(ts);
  return `${WEEK[d.getDay()]} ${pad(d.getHours())}:00`;
};

export function age(ts, now = Date.now()) {
  const s = Math.max(0, (now - ts) / 1000);
  if (s < 60) return "now";
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} d`;
}
export const ago = (ts) =>
  ts ? (Date.now() - ts < 60e3 ? "just now" : `${age(ts)} ago`) : "never";
export const num = (n) => Number(n ?? 0).toLocaleString("en-US");
export const kfmt = (n) =>
  n >= 1000 ? `${(n / 1000).toFixed(n >= 10000 ? 1 : 1)}k` : String(n);
export const dur = (ms) => {
  if (ms === null || ms === undefined) return "—";
  const s = Math.round(ms / 1000);
  return s >= 60 ? `${Math.floor(s / 60)}m ${pad(s % 60)}s` : `${s}s`;
};
export const initials = (name) =>
  (name || "")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0].toUpperCase())
    .join("") || "—";

const SEV = {
  critical: ["crit", "Critical"],
  high: ["high", "High"],
  medium: ["med", "Medium"],
  low: ["low", "Low"],
  info: ["info", "Info"],
};
export const sevBadge = (s) =>
  `<span class="b ${(SEV[s] || SEV.info)[0]}">${(SEV[s] || SEV.info)[1]}</span>`;
export const sevLabel = (s) => (SEV[s] || SEV.info)[1];
const STATUS = {
  open: ["crit", "Open"],
  acknowledged: ["med", "Acknowledged"],
  resolved: ["low", "Resolved"],
};
export const statusBadge = (s) =>
  `<span class="b ${STATUS[s][0]}">${STATUS[s][1]}</span>`;
export const roleBadge = (r) =>
  `<span class="b ${{ admin: "crit", analyst: "info", viewer: "low" }[r]}">${r[0].toUpperCase() + r.slice(1)}</span>`;

export const toggle = (
  on,
  { label, attrs = "", disabled = false, title = "" } = {},
) =>
  `<button type="button" class="tgw" role="switch" aria-checked="${on}" aria-label="${esc(label || "Toggle")}" ${disabled ? "disabled" : ""} ${title ? `title="${esc(title)}"` : ""} ${attrs}><span class="tg ${on ? "" : "off"}"></span></button>`;

export function seg(options, current, attr = "data-seg") {
  return `<div class="seg">${options.map(([v, l]) => `<button type="button" ${attr}="${esc(v)}" class="${v === current ? "on" : ""}">${l}</button>`).join("")}</div>`;
}

export function pager(page, pages, total, pageSize) {
  const from = total ? (page - 1) * pageSize + 1 : 0,
    to = Math.min(total, page * pageSize);
  const start = Math.max(1, Math.min(page - 2, pages - 4)),
    end = Math.min(pages, start + 4);
  const btns = [];
  for (let i = start; i <= end; i++)
    btns.push(
      `<button type="button" data-pg="${i}" class="${i === page ? "on" : ""}">${i}</button>`,
    );
  return `<div class="pg"><span>Showing ${num(from)}–${num(to)} of ${num(total)}</span><div class="seg"><button type="button" data-pg="${page - 1}" ${page <= 1 ? "disabled" : ""}>Prev</button>${btns.join("")}<button type="button" data-pg="${page + 1}" ${page >= pages ? "disabled" : ""}>Next</button></div></div>`;
}

/** Multi-select dropdown in the style of the design's "Severity ▾" buttons. */
export function filterMenu(id, label, options, selected) {
  const n = selected.size;
  return `<span class="pw" data-menu="${id}" data-label="${esc(label)}"><button type="button" class="btn${n ? " active" : ""}" data-pop aria-haspopup="true" aria-expanded="false">${esc(label)}${n ? ` · ${n}` : ""} <span class="mu">▾</span></button>
<div class="pop" hidden>${options.map(([v, l]) => `<label class="pi"><input type="checkbox" data-fopt="${id}" value="${esc(v)}" ${selected.has(v) ? "checked" : ""}> ${esc(l)}</label>`).join("")}<div class="pop-f"><button type="button" class="btn sm g0" data-fclear="${id}">Clear</button></div></div></span>`;
}
export function syncMenu(root, id, selected) {
  const w = root.querySelector(`[data-menu="${id}"]`);
  if (!w) return;
  const b = w.querySelector("[data-pop]");
  b.classList.toggle("active", selected.size > 0);
  b.innerHTML = `${esc(w.dataset.label)}${selected.size ? ` · ${selected.size}` : ""} <span class="mu">▾</span>`;
  w.querySelectorAll("input[data-fopt]").forEach((i) => {
    i.checked = selected.has(i.value);
  });
}

export function closePops(except) {
  document.querySelectorAll(".pop:not([hidden])").forEach((p) => {
    if (p !== except) {
      p.hidden = true;
      const b = p.parentElement.querySelector("[data-pop]");
      if (b) b.setAttribute("aria-expanded", "false");
    }
  });
}
export function togglePop(btn) {
  const pop = btn.parentElement.querySelector(".pop");
  const open = pop.hidden;
  closePops(open ? pop : null);
  pop.hidden = !open;
  btn.setAttribute("aria-expanded", String(open));
}

export function toast(msg, kind = "ok") {
  let host = document.getElementById("toasts");
  if (!host) {
    host = document.createElement("div");
    host.id = "toasts";
    host.setAttribute("aria-live", "polite");
    document.body.appendChild(host);
  }
  const t = document.createElement("div");
  t.className = `toast ${kind}`;
  t.textContent = msg;
  host.appendChild(t);
  setTimeout(
    () => {
      t.classList.add("out");
      setTimeout(() => t.remove(), 250);
    },
    kind === "err" ? 6000 : 3200,
  );
}

export const modalOpen = () => Boolean(document.querySelector(".ov"));

/**
 * Modal with a form. fields: html string. onSubmit(formData, close, form) may throw (message shown inline).
 * opts.dismissable=false for forced dialogs.
 */
export function modal({
  title,
  html,
  submitLabel = "Save",
  cancelLabel = "Cancel",
  danger = false,
  onSubmit,
  onMount,
  wide = false,
  dismissable = true,
  hideSubmit = false,
}) {
  const ov = document.createElement("div");
  ov.className = "ov";
  ov.innerHTML = `<form class="md c${wide ? " wide" : ""}" role="dialog" aria-modal="true" aria-label="${esc(title)}" novalidate>
<h2>${esc(title)}</h2><div class="mb">${html}</div><div class="merr" role="alert" hidden></div>
<div class="ft">${dismissable ? `<button type="button" class="btn" data-close>${esc(cancelLabel)}</button>` : "<span></span>"}${hideSubmit ? "" : `<button type="submit" class="btn ${danger ? "danger" : "p"}">${esc(submitLabel)}</button>`}</div></form>`;
  const form = ov.querySelector("form");
  const prevFocus = document.activeElement;
  const close = () => {
    ov.remove();
    document.removeEventListener("keydown", onKey);
    if (prevFocus && prevFocus.focus) prevFocus.focus();
  };
  const onKey = (e) => {
    if (e.key === "Escape" && dismissable) close();
  };
  document.addEventListener("keydown", onKey);
  ov.addEventListener("mousedown", (e) => {
    if (e.target === ov && dismissable) close();
  });
  form
    .querySelectorAll("[data-close]")
    .forEach((b) => b.addEventListener("click", close));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = form.querySelector(".merr");
    err.hidden = true;
    const btn = form.querySelector("button[type=submit]");
    if (btn) btn.disabled = true;
    try {
      if (onSubmit) await onSubmit(new FormData(form), close, form);
    } catch (ex) {
      err.textContent = ex.message || "Something went wrong";
      err.hidden = false;
    } finally {
      if (btn && document.body.contains(form)) btn.disabled = false;
    }
  });
  document.body.appendChild(ov);
  if (onMount) onMount(form, close);
  const first = form.querySelector("input:not([type=hidden]),select,textarea");
  if (first) first.focus();
  return { close, form };
}

export function confirmBox({
  title,
  text,
  confirmLabel = "Confirm",
  danger = false,
}) {
  return new Promise((resolve) => {
    let done = false;
    const m = modal({
      title,
      html: `<p class="mu" style="margin:0">${esc(text)}</p>`,
      submitLabel: confirmLabel,
      danger,
      onSubmit: (_f, close) => {
        done = true;
        close();
        resolve(true);
      },
    });
    new MutationObserver((_r, o) => {
      if (!document.body.contains(m.form)) {
        o.disconnect();
        if (!done) resolve(false);
      }
    }).observe(document.body, { childList: true });
  });
}

export const field = (label, control, hint = "") =>
  `<label class="fld"><span>${esc(label)}</span>${control}${hint ? `<small class="mu">${esc(hint)}</small>` : ""}</label>`;
export const options = (list, sel) =>
  list
    .map(
      ([v, l]) =>
        `<option value="${esc(v)}" ${String(v) === String(sel) ? "selected" : ""}>${esc(l)}</option>`,
    )
    .join("");

export function debounce(fn, ms) {
  let t;
  return (...a) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...a), ms);
  };
}

export const demoFoot = (meta) =>
  meta && meta.demoMode
    ? '<div class="foot">Illustrative demo data only. No real security data is shown; IPs use reserved documentation ranges.</div>'
    : "";
