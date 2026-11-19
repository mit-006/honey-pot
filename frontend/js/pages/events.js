import { get, post, del, qs } from "../api.js";
import {
  $,
  $$,
  confirmBox,
  debounce,
  esc,
  filterMenu,
  fullTime,
  num,
  pager,
  seg,
  sevBadge,
  syncMenu,
  timeCell,
  toast,
  togglePop,
  closePops,
} from "../ui.js";

const SEVS = [
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["info", "Info"],
];
const S = {
  range: "24h",
  q: "",
  sev: new Set(),
  decoy: new Set(),
  proto: new Set(),
  page: 1,
  sel: null,
  checked: new Set(),
};

const params = () => ({
  range: S.range,
  q: S.q,
  severity: S.sev,
  decoy: S.decoy,
  protocol: S.proto,
});

export async function mount(ctx) {
  const { root, can } = ctx;
  let opts = { decoys: [], protocols: [] };
  let data = { rows: [], total: 0, page: 1, pages: 1, pageSize: 12 };
  let detail = null;
  const urlSel = Number(ctx.params.get("sel"));
  if (urlSel) {
    S.sel = urlSel;
    S.page = 1;
  }

  async function fetchList() {
    data = await get(
      "/events" + qs({ ...params(), page: S.page, pageSize: 12 }),
    );
    opts = data.options;
    S.page = data.page;
  }
  async function fetchDetail() {
    if (!S.sel) {
      detail = null;
      return;
    }
    try {
      detail = await get(`/events/${S.sel}`);
    } catch {
      detail = null;
      S.sel = null;
    }
  }

  function skeleton() {
    root.innerHTML = `
<div class="h"><div><h1>Security Events</h1><div class="sub" id="sub"></div></div><div class="row"></div></div>
<div class="c bar"><div class="row"><input class="in" id="q" style="width:280px;max-width:100%" placeholder="Search IP, decoy, payload" aria-label="Search events" value="${esc(S.q)}">
${filterMenu("sev", "Severity", SEVS, S.sev)}${filterMenu(
      "decoy",
      "Decoy",
      opts.decoys.map((d) => [d, d]),
      S.decoy,
    )}${filterMenu(
      "proto",
      "Protocol",
      opts.protocols.map((p) => [p, p]),
      S.proto,
    )}</div>
<div class="row"><div id="rng"></div><button class="btn" type="button" id="exp"></button></div></div>
<div class="w"><section class="c"><h3><span>Events</span><span style="text-transform:none;letter-spacing:0;font-weight:500"></span></h3><div class="sc" id="tbl"></div><div id="pgr"></div></section><section class="c" id="det"></section></div>`;
  }

  function renderRange() {
    $(root, "#rng").innerHTML = seg(
      [
        ["1h", "1h"],
        ["24h", "24h"],
        ["7d", "7d"],
      ],
      S.range,
    );
  }
  function renderTable() {
    const allOn =
      data.rows.length && data.rows.every((r) => S.checked.has(r.id));
    $(root, "#sub").textContent =
      `${num(data.total)} events match current filters${S.checked.size ? ` · ${S.checked.size} selected` : ""}`;
    $(root, "#exp").textContent = S.checked.size
      ? `Export selected (${S.checked.size})`
      : "Export CSV";
    $(root, "#tbl").innerHTML =
      `<table class="t"><thead><tr><th><input type="checkbox" data-all aria-label="Select all rows" ${allOn ? "checked" : ""}></th><th>ID</th><th>Time</th><th>Severity</th><th>Decoy</th><th>Source</th><th>Type</th></tr></thead><tbody>
${data.rows.length ? data.rows.map((e) => `<tr data-id="${e.id}" class="${e.id === S.sel ? "sel" : ""}"><td><input type="checkbox" data-chk="${e.id}" aria-label="Select row" ${S.checked.has(e.id) ? "checked" : ""}></td><td><span class="m">EVT-${e.id}</span></td><td><span class="m">${timeCell(e.ts)}</span></td><td>${sevBadge(e.severity)}</td><td>${esc(e.decoy)}</td><td><span class="m">${esc(e.src_ip)}</span></td><td>${esc(e.summary)}</td></tr>`).join("") : '<tr class="empty-row"><td colspan="7">No events match these filters.</td></tr>'}
</tbody></table>`;
    $(root, "#pgr").innerHTML = data.total
      ? pager(data.page, data.pages, data.total, data.pageSize)
      : "";
  }

  function renderDetail() {
    const box = $(root, "#det");
    if (!detail) {
      box.innerHTML =
        '<h3><span>Event details</span></h3><div class="ph">Select an event to see its details.</div>';
      return;
    }
    const e = detail;
    const hasAlert = Boolean(e.alert);
    box.innerHTML = `<h3><span>EVT-${e.id}</span><span style="text-transform:none;letter-spacing:0;font-weight:500">${e.simulated ? "simulated" : "sensor"}</span></h3>${sevBadge(e.severity)}
<div class="kv"><span>Time</span><span class="m">${fullTime(e.ts)}</span></div>
<div class="kv"><span>Decoy</span>${esc(e.decoy)}</div>
<div class="kv"><span>Source</span><span class="m">${esc(e.src_ip)} · ${esc(e.country)}</span></div>
<div class="kv"><span>Protocol</span><span class="m">${esc(e.protocol)} / ${e.port}</span></div>
<div class="kv"><span>Attempts</span><span class="m">${num(e.attempts)}${e.duration_s ? ` in ${e.duration_s} s` : ""}</span></div>
${e.payload ? `<pre>${esc(e.payload)}</pre>` : ""}
<div class="mu" style="margin:6px 0">Related from same source${e.sourceCount > 1 ? ` (${num(e.sourceCount)} total)` : ""}</div>
${e.related.length ? e.related.map((r) => `<div class="kv"><a href="#/events?sel=${r.id}" class="m" style="text-decoration:none">${timeCell(r.ts)}</a><span class="m">${esc(r.decoy)} · ${esc(r.summary)}</span></div>`).join("") : '<div class="kv"><span>None</span></div>'}
<div class="ft"><button class="btn p" type="button" data-act="alert" ${!can.analyst || hasAlert ? "disabled" : ""} title="${!can.analyst ? "Requires analyst role" : hasAlert ? `Alert ${e.alert.code} exists` : ""}">${hasAlert ? "Alert exists" : "Create alert"}</button>
<button class="btn" type="button" data-act="block" ${!can.analyst ? 'disabled title="Requires analyst role"' : ""}>${e.blocked ? "Unblock IP" : "Block IP"}</button></div>`;
  }

  async function reload() {
    await fetchList();
    if (!data.rows.some((r) => r.id === S.sel))
      S.sel = data.rows[0] ? data.rows[0].id : null;
    await fetchDetail();
    renderTable();
    renderDetail();
  }

  await fetchList();
  skeleton();
  renderRange();
  if (!S.sel && data.rows[0]) S.sel = data.rows[0].id;
  await fetchDetail();
  renderTable();
  renderDetail();

  const search = debounce(() => {
    S.q = $(root, "#q").value.trim();
    S.page = 1;
    reload();
  }, 300);
  root.addEventListener("input", (e) => {
    if (e.target.id === "q") search();
  });

  root.addEventListener("change", (e) => {
    const t = e.target;
    if (t.dataset.fopt) {
      const set = S[t.dataset.fopt];
      t.checked ? set.add(t.value) : set.delete(t.value);
      syncMenu(root, t.dataset.fopt, set);
      S.page = 1;
      reload();
      return;
    }
    if (t.matches("[data-all]")) {
      data.rows.forEach((r) =>
        t.checked ? S.checked.add(r.id) : S.checked.delete(r.id),
      );
      renderTable();
      return;
    }
    if (t.dataset.chk) {
      const id = Number(t.dataset.chk);
      t.checked ? S.checked.add(id) : S.checked.delete(id);
      renderTable();
    }
  });

  root.addEventListener("click", async (e) => {
    const t = e.target;
    const pop = t.closest("[data-pop]");
    if (pop) {
      togglePop(pop);
      return;
    }
    const clr = t.closest("[data-fclear]");
    if (clr) {
      const k = clr.dataset.fclear;
      S[k].clear();
      syncMenu(root, k, S[k]);
      S.page = 1;
      reload();
      return;
    }
    const sg = t.closest("[data-seg]");
    if (sg) {
      S.range = sg.dataset.seg;
      S.page = 1;
      renderRange();
      reload();
      return;
    }
    const pg = t.closest("[data-pg]");
    if (pg && !pg.disabled) {
      S.page = Number(pg.dataset.pg);
      reload();
      return;
    }
    if (t.closest("#exp")) {
      window.location.href =
        "/api/events/export.csv" + qs({ ...params(), ids: S.checked });
      return;
    }
    const act = t.closest("[data-act]");
    if (act && detail) {
      act.disabled = true;
      try {
        if (act.dataset.act === "alert") {
          const a = await post(`/events/${detail.id}/alert`);
          toast(`Alert ${a.code} created`);
          ctx.refreshBadge();
        }
        if (act.dataset.act === "block") {
          if (detail.blocked) {
            await del(`/events/${detail.id}/block-ip`);
            toast(`${detail.src_ip} removed from the blocklist`);
          } else if (
            await confirmBox({
              title: "Block IP",
              text: `Add ${detail.src_ip} to the blocklist? This records the IP for export to your perimeter tools; it does not change any firewall.`,
              confirmLabel: "Block IP",
            })
          ) {
            await post(`/events/${detail.id}/block-ip`);
            toast(`${detail.src_ip} added to the blocklist`);
          }
        }
        await fetchDetail();
        renderDetail();
      } catch (ex) {
        toast(ex.message, "err");
        act.disabled = false;
      }
      return;
    }
    if (t.closest("input,a,label")) return;
    const row = t.closest("tr[data-id]");
    if (row) {
      S.sel = Number(row.dataset.id);
      $$(root, "tr[data-id]").forEach((r) =>
        r.classList.toggle("sel", r === row),
      );
      await fetchDetail();
      renderDetail();
    }
  });

  return {
    live: async () => {
      if (S.page === 1 && !S.checked.size) {
        await fetchList();
        renderTable();
      }
    },
    destroy: () => closePops(),
  };
}
