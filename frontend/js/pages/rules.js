import { del, get, patch, post, qs } from "../api.js";
import {
  $,
  $$,
  ago,
  confirmBox,
  debounce,
  esc,
  field,
  filterMenu,
  modal,
  options,
  sevBadge,
  syncMenu,
  toast,
  toggle,
  togglePop,
} from "../ui.js";

const SEVS = [
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["info", "Info"],
];
const METRICS = [
  ["count", "event count"],
  ["attempts", "sum of attempts"],
  ["distinct", "distinct values"],
];
const S = { q: "", sev: new Set(), state: "all", sel: null };

export async function mount(ctx) {
  const { root, can } = ctx;
  let data = { rules: [], total: 0, enabled: 0 };
  let meta = null;
  let draft = null; // unsaved edits for the selected rule

  const load = async () => {
    data = await get(
      "/rules" + qs({ q: S.q, severity: S.sev, state: S.state }),
    );
    if (!data.rules.some((r) => r.id === S.sel)) {
      S.sel = data.rules[0] ? data.rules[0].id : null;
      draft = null;
    }
  };
  const sel = () => data.rules.find((r) => r.id === S.sel);

  function skeleton() {
    root.innerHTML = `
<div class="h"><div><h1>Detection Rules</h1><div class="sub" id="sub"></div></div><div class="row"><button class="btn p" type="button" data-new ${can.analyst ? "" : 'disabled title="Requires analyst role"'}>+ New rule</button></div></div>
<div class="c bar"><div class="row"><input class="in" id="q" style="width:260px;max-width:100%" placeholder="Search rules" aria-label="Search rules" value="${esc(S.q)}">${filterMenu("sev", "Severity", SEVS, S.sev)}</div><div id="st"></div></div>
<div class="w"><section class="c"><h3><span>Rules</span><span style="text-transform:none;letter-spacing:0;font-weight:500"></span></h3><div class="sc" id="tbl"></div></section><section class="c" id="panel"></section></div>`;
  }

  function renderTable() {
    $(root, "#sub").textContent =
      `${data.total} rules · ${data.enabled} enabled`;
    $(root, "#st").innerHTML = `<div class="seg">${[
      ["all", "All"],
      ["enabled", "Enabled"],
      ["disabled", "Disabled"],
    ]
      .map(
        ([v, l]) =>
          `<button type="button" data-seg="${v}" class="${S.state === v ? "on" : ""}">${l}</button>`,
      )
      .join("")}</div>`;
    $(root, "#tbl").innerHTML =
      `<table class="t"><thead><tr><th>On</th><th>Rule</th><th>Condition</th><th>Threshold</th><th>Severity</th><th>Hits 24h</th><th>Last hit</th></tr></thead><tbody>
${data.rules.length ? data.rules.map((r) => `<tr data-rule="${r.id}" class="${r.id === S.sel ? "sel" : ""}"><td>${toggle(r.enabled, { label: `${r.enabled ? "Disable" : "Enable"} ${r.name}`, attrs: `data-tg="${r.id}"`, disabled: !can.analyst, title: can.analyst ? "" : "Requires analyst role" })}</td><td>${esc(r.name)}</td><td><span class="m">${esc(r.condition_text)}</span></td><td><span class="m">${r.op === ">=" ? "≥" : "&gt;"} ${r.threshold}</span></td><td>${sevBadge(r.severity)}</td><td><span class="m">${r.hits24}</span></td><td>${ago(r.lastHit)}</td></tr>`).join("") : '<tr class="empty-row"><td colspan="7">No rules match these filters.</td></tr>'}</tbody></table>`;
  }

  function renderPanel() {
    const r = sel();
    const box = $(root, "#panel");
    if (!r) {
      box.innerHTML =
        '<h3><span>Rule details</span></h3><div class="ph">Select a rule to view or edit it.</div>';
      return;
    }
    const v = { ...r, ...(draft || {}) };
    const ro = can.analyst ? "" : "disabled";
    box.innerHTML = `<h3><span>${esc(r.name)}</span><span style="text-transform:none;letter-spacing:0;font-weight:500" class="m">${esc(r.code)}</span></h3>
<div class="kv"><span>Matches</span><select class="in sm" data-f="match_type" ${ro}>${options(
      meta.types.map((t) => [t.key, t.label]),
      v.match_type,
    )}</select></div>
<div class="kv"><span>Condition</span><span class="row" style="flex-wrap:nowrap"><select class="in sm" data-f="metric" ${ro}>${options(METRICS, v.metric)}</select><select class="in sm" data-f="op" ${ro}>${options(
      [
        [">", ">"],
        [">=", "≥"],
      ],
      v.op,
    )}</select><input class="in sm num m" type="number" min="0" data-f="threshold" value="${v.threshold}" ${ro} aria-label="Threshold"></span></div>
<div class="kv"><span>Window</span><span class="row" style="flex-wrap:nowrap"><input class="in sm num m" type="number" min="1" max="86400" data-f="window_s" value="${v.window_s}" ${ro} aria-label="Window seconds"> <span class="m mu">s</span></span></div>
<div class="kv"><span>Group by</span><span class="m">${esc(r.group_by)}</span></div>
<div class="kv"><span>Severity</span><select class="in sm" data-f="severity" ${ro}>${options(SEVS, v.severity)}</select></div>
<div class="kv"><span>Notify</span><select class="in sm" data-f="notify" ${ro}>${options(
      [
        ["Dashboard", "Dashboard"],
        ["Email + dashboard", "Email + dashboard"],
      ],
      v.notify,
    )}</select></div>
<div class="kv"><span>Enabled</span>${toggle(Boolean(v.enabled), { label: "Enabled", attrs: "data-f-enabled", disabled: !can.analyst })}</div>
<div class="ft"><button class="btn p" type="button" data-save ${can.analyst && draft ? "" : "disabled"}>Save changes</button><span class="row"><button class="btn" type="button" data-test ${can.analyst ? "" : "disabled"}>Test rule</button>${can.admin ? '<button class="btn danger" type="button" data-del>Delete</button>' : ""}</span></div>`;
  }

  const refresh = async () => {
    await load();
    renderTable();
    renderPanel();
  };

  function newRule() {
    modal({
      title: "New detection rule",
      submitLabel: "Create rule",
      wide: true,
      html: `<div class="g2">${field("Name", '<input class="in" name="name" maxlength="60" required>')}${field("Code", '<input class="in" name="code" maxlength="16" placeholder="SSH-SPRAY" style="text-transform:uppercase" required>', "Prefix for alert IDs")}</div>
${field(
  "Matches event type",
  `<select class="in" name="match_type">${options(
    meta.types.map((t) => [t.key, `${t.label} (${t.key})`]),
    "",
  )}</select>`,
)}
<div class="g2">${field("Metric", `<select class="in" name="metric">${options(METRICS, "count")}</select>`)}${field(
        "Operator",
        `<select class="in" name="op">${options(
          [
            [">", "greater than"],
            [">=", "at least"],
          ],
          ">=",
        )}</select>`,
      )}</div>
<div class="g2">${field("Threshold", '<input class="in" type="number" name="threshold" min="0" value="5" required>')}${field("Window (seconds)", '<input class="in" type="number" name="window_s" min="1" max="86400" value="300" required>')}</div>
<div class="g2">${field("Severity", `<select class="in" name="severity">${options(SEVS, "medium")}</select>`)}${field(
        "Notify",
        `<select class="in" name="notify">${options(
          [
            ["Dashboard", "Dashboard"],
            ["Email + dashboard", "Email + dashboard"],
          ],
          "Dashboard",
        )}</select>`,
      )}</div>`,
      onSubmit: async (fd, close) => {
        const r = await post("/rules", Object.fromEntries([...fd.entries()]));
        close();
        toast("Rule created");
        S.sel = r.id;
        draft = null;
        await refresh();
      },
    });
  }

  meta = await get("/rules/meta");
  await load();
  skeleton();
  renderTable();
  renderPanel();

  const search = debounce(() => {
    S.q = $(root, "#q").value.trim();
    refresh();
  }, 300);
  root.addEventListener("input", (e) => {
    if (e.target.id === "q") search();
  });

  root.addEventListener("change", (e) => {
    const t = e.target;
    if (t.dataset.fopt) {
      t.checked ? S.sev.add(t.value) : S.sev.delete(t.value);
      syncMenu(root, "sev", S.sev);
      refresh();
      return;
    }
    if (t.dataset.f) {
      draft = draft || {};
      draft[t.dataset.f] = ["threshold", "window_s"].includes(t.dataset.f)
        ? Number(t.value)
        : t.value;
      $(root, "[data-save]").disabled = false;
    }
  });

  root.addEventListener("click", async (e) => {
    const t = e.target;
    const pop = t.closest("[data-pop]");
    if (pop) {
      togglePop(pop);
      return;
    }
    if (t.closest("[data-fclear]")) {
      S.sev.clear();
      syncMenu(root, "sev", S.sev);
      refresh();
      return;
    }
    const sg = t.closest("[data-seg]");
    if (sg) {
      S.state = sg.dataset.seg;
      refresh();
      return;
    }
    if (t.closest("[data-new]")) {
      newRule();
      return;
    }
    const tg = t.closest("[data-tg]");
    if (tg) {
      e.stopPropagation();
      const r = data.rules.find((x) => x.id === Number(tg.dataset.tg));
      try {
        await patch(`/rules/${r.id}`, { enabled: !r.enabled });
        toast(`${r.name} ${r.enabled ? "disabled" : "enabled"}`);
        await refresh();
      } catch (ex) {
        toast(ex.message, "err");
      }
      return;
    }
    if (t.closest("[data-f-enabled]")) {
      draft = draft || {};
      const cur = draft.enabled !== undefined ? draft.enabled : sel().enabled;
      draft.enabled = !cur;
      renderPanel();
      return;
    }
    if (t.closest("[data-save]")) {
      const r = sel();
      try {
        await patch(`/rules/${r.id}`, {
          ...draft,
          enabled: draft.enabled === undefined ? undefined : draft.enabled,
        });
        draft = null;
        toast("Rule saved");
        await refresh();
      } catch (ex) {
        toast(ex.message, "err");
      }
      return;
    }
    if (t.closest("[data-test]")) {
      const r = sel();
      try {
        const res = await post(
          `/rules/${r.id}/test`,
          draft
            ? Object.fromEntries(
                Object.entries(draft).filter(([k]) => k !== "enabled"),
              )
            : {},
        );
        modal({
          title: `Test: ${r.name}`,
          hideSubmit: true,
          cancelLabel: "Close",
          html: `<p style="margin-top:0">Replayed against the last ${res.windowH} hours of stored events (read-only, nothing is created).</p>
<div class="st"><div class="mu">Events scanned<b>${res.scanned.toLocaleString("en-US")}</b></div><div class="mu">Threshold hits<b>${res.hits.toLocaleString("en-US")}</b></div><div class="mu">Alerts it would raise<b>${res.alerts}</b></div></div><p class="mu" style="margin-bottom:0">${res.sources} distinct source${res.sources === 1 ? "" : "s"} crossed the threshold.</p>`,
        });
      } catch (ex) {
        toast(ex.message, "err");
      }
      return;
    }
    if (t.closest("[data-del]")) {
      const r = sel();
      if (
        await confirmBox({
          title: "Delete rule",
          text: `Delete "${r.name}"? Existing alerts stay, but the rule stops detecting.`,
          confirmLabel: "Delete",
          danger: true,
        })
      ) {
        try {
          await del(`/rules/${r.id}`);
          toast("Rule deleted");
          draft = null;
          await refresh();
        } catch (ex) {
          toast(ex.message, "err");
        }
      }
      return;
    }
    const row = t.closest("tr[data-rule]");
    if (row) {
      S.sel = Number(row.dataset.rule);
      draft = null;
      $$(root, "tr[data-rule]").forEach((x) =>
        x.classList.toggle("sel", x === row),
      );
      renderPanel();
    }
  });

  return {
    live: async () => {
      if (!draft) await refresh();
    },
  };
}
