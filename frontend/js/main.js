import { ApiError, get, post } from "./api.js";
import {
  closePops,
  debounce,
  field,
  modal,
  modalOpen,
  sevLabel,
  toast,
  togglePop,
  age,
} from "./ui.js";

const ROUTES = [
  ["overview", "Overview"],
  ["events", "Events"],
  ["alerts", "Alerts"],
  ["decoys", "Decoys"],
  ["rules", "Rules"],
  ["analytics", "Analytics"],
  ["audit", "Audit & Settings"],
];
const SEV_DOT = {
  critical: "#FF6B81",
  high: "#FFA94D",
  medium: "#FFD43B",
  low: "#4DD4AC",
  info: "#7CC4FF",
};

const app = document.getElementById("app");
const S = {
  user: null,
  meta: { demoMode: true },
  unread: 0,
  openAlerts: null,
  page: null,
  route: null,
  es: null,
  timer: null,
};

// Trusted, hard-coded SVG constants only. Never put server/user data in these.
const LOGO = `<svg width="26" height="26" viewBox="0 0 28 28" aria-hidden="true"><circle cx="14" cy="14" r="12" fill="none" stroke="#22D3EE" stroke-width="2"/><circle cx="14" cy="14" r="6.5" fill="none" stroke="#22D3EE" stroke-width="2" opacity=".55"/><circle cx="14" cy="14" r="2.5" fill="#22D3EE"/></svg>`;
const BELL = `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10 21h4"/></svg>`;

const can = () => ({
  analyst: ["analyst", "admin"].includes(S.user.role),
  admin: S.user.role === "admin",
});
const shortName = (n) => {
  const p = n.trim().split(/\s+/);
  return p.length > 1 ? `${p[0][0]}. ${p[p.length - 1]}` : n;
};
const initials = (n) =>
  n
    .trim()
    .split(/\s+/)
    .slice(0, 2)
    .map((w) => w[0].toUpperCase())
    .join("");

// ---------------------------------------------------------------- safe DOM helpers
function svgNode(svgString) {
  return new DOMParser().parseFromString(svgString, "image/svg+xml")
    .documentElement;
}

// Only allow in-app hash links (blocks javascript: and external URLs)
const safeLink = (l) =>
  typeof l === "string" && l.startsWith("#/") ? l : "#/alerts";

// TODO: replace class names / text with the ones from your old roleBadge() in ui.js
function roleBadgeNode(role) {
  const s = document.createElement("span");
  s.className = "badge";
  s.textContent = role;
  return s;
}

// TODO: replace class name / text with the ones from your old demoFoot() in ui.js
function demoFootNode(meta) {
  const p = document.createElement("p");
  p.className = "foot";
  p.textContent = meta.demoMode
    ? "Demo build · simulated telemetry only."
    : "";
  return p;
}

// ---------------------------------------------------------------- login
function renderLogin(message = "") {
  closeStream();

  // Static markup only. The message is added below via textContent.
  const tpl = document.createElement("template");
  tpl.innerHTML = `<main class="login" id="main"><form class="c" id="lf" novalidate>
<div class="logo" id="login-logo">HONEYPOT ATLAS</div><h1>Sign in</h1><div class="sub">Cyber Threat Observatory</div>
${field("Username", '<input class="in" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required>')}
${field("Password", '<input class="in" type="password" name="password" autocomplete="current-password" required>')}
<div class="merr" id="le" role="alert" hidden></div>
<div style="margin-top:12px"><button class="btn p" type="submit">Sign in</button></div>
<p class="foot" id="demo-note" style="text-align:center;margin:14px 0 0" hidden>Demo build · simulated telemetry only.<br>Seeded accounts: a.rivera (admin) · s.kapoor (analyst) · m.chen (viewer)</p>
</form></main>`;
  app.replaceChildren(tpl.content);

  document.getElementById("login-logo").prepend(svgNode(LOGO));
  document.getElementById("demo-note").hidden = !S.meta.demoMode;
  const le = document.getElementById("le");
  if (message) {
    le.textContent = message;
    le.hidden = false;
  }

  const f = document.getElementById("lf");
  f.username.focus();
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = f.querySelector("button");
    btn.disabled = true;
    try {
      const r = await post("/auth/login", {
        username: f.username.value.trim(),
        password: f.password.value,
      });
      S.user = r.user;
      startShell();
    } catch (ex) {
      const el = document.getElementById("le");
      el.textContent = ex.message;
      el.hidden = false;
      btn.disabled = false;
      f.password.select();
    }
  });
}

// ---------------------------------------------------------------- shell
function startShell() {
  const c = can();

  // Static markup only: no ${} inside, so no user data can enter here
  const tpl = document.createElement("template");
  tpl.innerHTML = `<header class="nav"><div class="logo" id="logo">HONEYPOT ATLAS</div>
<nav class="tabs" aria-label="Main" id="tabs"></nav>
<span class="demo" id="demo-badge" title="All telemetry is simulated" hidden>DEMO DATA</span>
<span class="pw"><button class="ib" id="bell" type="button" data-pop aria-haspopup="true" aria-expanded="false" aria-label="Notifications"><i id="bell-dot" hidden></i></button>
<div class="pop right nt" id="notif" hidden></div></span>
<span class="pw"><button class="av" type="button" data-pop aria-haspopup="true" aria-expanded="false"><b id="u-initials"></b><span id="u-short"></span></button>
<div class="pop right" id="umenu" hidden><div class="hd"><b id="u-name"></b><span class="mu m" id="u-username"></span> </div>
<button class="it" type="button" data-act="pw">Change password</button><button class="it" type="button" data-act="logout">Sign out</button></div></span></header>
<main class="wrap" id="main"><div id="slot"></div><div id="foot"></div></main>`;
  app.replaceChildren(tpl.content);

  // Icons (your own constants)
  document.querySelector("#logo").prepend(svgNode(LOGO));
  document.querySelector("#bell").prepend(svgNode(BELL));

  // Tabs built with the DOM API
  const tabs = document.querySelector("#tabs");
  for (const [k, l] of ROUTES) {
    const a = document.createElement("a");
    a.href = `#/${k}`;
    a.dataset.route = k;
    a.append(l);
    if (k === "alerts") {
      const n = document.createElement("span");
      n.className = "n";
      n.id = "alert-n";
      n.hidden = true;
      a.append(n);
    }
    tabs.append(a);
  }

  // User data goes in as text only
  document.querySelector("#demo-badge").hidden = !S.meta.demoMode;
  document.querySelector("#u-initials").textContent = initials(S.user.name);
  document.querySelector("#u-short").textContent =
    `${shortName(S.user.name)} ▾`;
  document.querySelector("#u-name").textContent = S.user.name;
  document.querySelector("#u-username").textContent = `@${S.user.username}`;
  document.querySelector(".hd").append(roleBadgeNode(S.user.role));
  document.querySelector("#foot").append(demoFootNode(S.meta));

  document.querySelector("#slot").style.display = "contents";
  document.querySelector("#foot").style.display = "contents";
  bindShell(c);
  refreshBadge();
  openStream();
  navigate();
  if (S.user.must_change) forcePasswordChange();
}

function bindShell() {
  const nav = app.querySelector(".nav");
  nav.addEventListener("click", async (e) => {
    const pop = e.target.closest("[data-pop]");
    if (pop) {
      togglePop(pop);
      if (pop.id === "bell") renderNotifications();
      return;
    }
    const act = e.target.closest("[data-act]");
    if (!act) return;
    closePops();
    if (act.dataset.act === "logout") {
      try {
        await post("/auth/logout");
      } catch {
        /* ignore */
      }
      S.user = null;
      renderLogin();
    }
    if (act.dataset.act === "pw") passwordModal(false);
  });
  document.getElementById("notif").addEventListener("click", async (e) => {
    if (e.target.closest("[data-readall]")) {
      await post("/notifications/read");
      await refreshBadge();
      renderNotifications();
    }
    if (e.target.closest("a")) closePops();
  });
}

document.addEventListener("click", (e) => {
  if (!e.target.closest(".pw")) closePops();
});
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closePops();
});
window.addEventListener("hashchange", () => {
  if (S.user) navigate();
});
window.addEventListener("atlas:unauth", () => {
  if (S.user) {
    S.user = null;
    document.querySelectorAll(".ov").forEach((o) => o.remove());
    renderLogin("Your session has ended. Please sign in again.");
  }
});

// ---------------------------------------------------------------- notifications
function notifItem(n) {
  const a = document.createElement("a");
  a.href = safeLink(n.link);
  if (!n.read) a.className = "unread";

  const dot = document.createElement("i");
  dot.className = "dot";
  dot.style.background = Object.hasOwn(SEV_DOT, n.severity)
    ? SEV_DOT[n.severity]
    : "#7CC4FF";
  dot.style.marginTop = "5px";
  dot.style.flex = "none";

  const wrap = document.createElement("span");
  const b = document.createElement("b");
  b.textContent = n.text;
  const small = document.createElement("small");
  small.textContent = `${sevLabel(n.severity)} · ${age(n.ts)} ago`;
  wrap.append(b, small);

  a.append(dot, wrap);
  return a;
}

async function renderNotifications() {
  const box = document.getElementById("notif");
  try {
    const r = await get("/notifications");

    const top = document.createElement("div");
    top.className = "top";
    const title = document.createElement("span");
    title.textContent = "Notifications";
    const btn = document.createElement("button");
    btn.className = "btn sm g0";
    btn.type = "button";
    btn.dataset.readall = "";
    btn.disabled = !r.unread;
    btn.textContent = "Mark all read";
    top.append(title, btn);

    const list = document.createElement("div");
    list.className = "list";
    if (r.items.length) {
      list.append(...r.items.map(notifItem));
    } else {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "No notifications yet.";
      list.append(empty);
    }

    box.replaceChildren(top, list);
  } catch (ex) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = ex.message;
    box.replaceChildren(empty);
  }
}

export async function refreshBadge() {
  try {
    const [n, a] = await Promise.all([
      get("/notifications"),
      get("/alerts/counts"),
    ]);
    S.unread = n.unread;
    S.openAlerts = a.open;
    const bell = document.getElementById("bell");
    if (!bell) return;
    bell.setAttribute("aria-label", `Notifications, ${n.unread} unread`);
    document.getElementById("bell-dot").hidden = n.unread === 0;
    const badge = document.getElementById("alert-n");
    badge.hidden = a.open === 0;
    badge.textContent = a.open;
  } catch {
    /* transient */
  }
}

// ---------------------------------------------------------------- passwords
function passwordModal(forced) {
  let heading = "Change password";
  if (forced) heading = "Set a new password";

  modal({
    title: heading,
    dismissable: !forced,
    submitLabel: "Save changes",
    html: `${forced ? '<p class="mu" style="margin-top:0">Your account uses a temporary password. Choose a new one (10+ characters) to continue.</p>' : ""}
${field("Current password", '<input class="in" type="password" name="current" autocomplete="current-password" required>')}
${field("New password", '<input class="in" type="password" name="next" autocomplete="new-password" minlength="10" required>', "10–128 characters")}
${field("Confirm new password", '<input class="in" type="password" name="again" autocomplete="new-password" required>')}`,
    onSubmit: async (fd, close) => {
      if (fd.get("next") !== fd.get("again"))
        throw new Error("New passwords do not match");
      await post("/auth/password", {
        current: fd.get("current"),
        next: fd.get("next"),
      });
      S.user.must_change = false;
      close();
      toast("Password updated");
    },
  });
}
const forcePasswordChange = () => passwordModal(true);

// ---------------------------------------------------------------- routing
function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [name, query = ""] = raw.split("?");
  return {
    name: ROUTES.some(([k]) => k === name) ? name : "overview",
    params: new URLSearchParams(query),
  };
}

function loadError(message) {
  const box = document.createElement("div");
  box.className = "c ph";
  box.append(`Could not load this page: ${message}`);

  const wrap = document.createElement("div");
  wrap.style.marginTop = "12px";
  const btn = document.createElement("button");
  btn.className = "btn";
  btn.type = "button";
  btn.id = "retry";
  btn.textContent = "Retry";
  btn.addEventListener("click", navigate);
  wrap.append(btn);

  box.append(wrap);
  return box;
}

async function navigate() {
  const { name, params } = parseHash();
  if (S.page && S.page.destroy) {
    try {
      S.page.destroy();
    } catch {
      /* ignore */
    }
  }
  S.page = null;
  S.route = name;
  closePops();
  document.querySelectorAll(".tabs a").forEach((a) => {
    const on = a.dataset.route === name;
    a.classList.toggle("on", on);
    if (on) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  const slot = document.getElementById("slot");
  const root = document.createElement("div");
  root.className = "page";
  const loading = document.createElement("div");
  loading.className = "loading";
  loading.textContent = "Loading…";
  root.append(loading);
  slot.replaceChildren(root);
  document.title = `${ROUTES.find(([k]) => k === name)[1]} · Honeypot Atlas`;
  window.scrollTo(0, 0);
  try {
    const mod = await import(`./pages/${name}.js`);
    if (S.route !== name || !root.isConnected) return;
    root.replaceChildren();
    S.page = await mod.mount({
      root,
      user: S.user,
      can: can(),
      meta: S.meta,
      params,
      refreshBadge,
      go: (h) => {
        location.hash = h;
      },
    });
  } catch (ex) {
    if (ex instanceof ApiError && ex.status === 401) return;
    root.replaceChildren(loadError(ex.message));
    console.error(ex);
  }
}

// ---------------------------------------------------------------- live updates
const live = debounce(() => {
  if (
    document.visibilityState !== "visible" ||
    modalOpen() ||
    document.querySelector(".pop:not([hidden])")
  )
    return;
  refreshBadge();
  if (S.page && S.page.live) S.page.live();
}, 2500);

function openStream() {
  closeStream();
  S.es = new EventSource("/api/stream");
  S.es.addEventListener("change", live);
  clearInterval(S.timer);
  S.timer = setInterval(() => {
    if (S.user && document.visibilityState === "visible") refreshBadge();
  }, 60000);
}
function closeStream() {
  if (S.es) {
    S.es.close();
    S.es = null;
  }
  clearInterval(S.timer);
}

// ---------------------------------------------------------------- boot
(async function boot() {
  try {
    S.meta = await get("/meta");
  } catch {
    /* keep defaults */
  }
  try {
    const r = await get("/auth/me");
    S.user = r.user;
    startShell();
  } catch {
    renderLogin();
  }
})();
