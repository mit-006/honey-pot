// Optional browser end-to-end check of the main workflows.
//   npm i --no-save puppeteer            (downloads Chromium)
//   E2E_URL=http://127.0.0.1:3000 node scripts/e2e.mjs
// Environment: E2E_PASSWORD (default atlas-demo-2026), CHROME_PATH (use an existing Chrome/Chromium),
//              PUPPETEER_MODULE (alternate import path for puppeteer / puppeteer-core)
import crypto from "node:crypto";

const { default: puppeteer } = await import(
  process.env.PUPPETEER_MODULE || "puppeteer"
);
const base = process.env.E2E_URL || "http://127.0.0.1:3000";
const password = process.env.E2E_PASSWORD || "atlas-demo-2026";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const check = (name, ok, extra = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? "  " + extra : ""}`);
  if (!ok) failures++;
};

const browser = await puppeteer.launch({
  headless: true,
  args: ["--no-sandbox"],
  executablePath: process.env.CHROME_PATH || undefined,
});
const page = await browser.newPage();
const jsErrors = [];
page.on("pageerror", (e) => jsErrors.push(e.message));
page.on("console", (m) => {
  if (
    m.type() === "error" &&
    !/ERR_NAME_NOT_RESOLVED|401|403|409|400/.test(m.text())
  )
    jsErrors.push(m.text());
});
await page.setViewport({ width: 1440, height: 900 });

const text = (sel) =>
  page.$eval(sel, (e) => e.textContent.trim()).catch(() => null);
const count = (sel) => page.$$eval(sel, (e) => e.length);
const go = async (route) => {
  await page.goto(`${base}/#/${route}`);
  await sleep(900);
};
const clickText = async (sel, label) => {
  const ok = await page.evaluate(
    (s, l) => {
      const b = [...document.querySelectorAll(s)].find(
        (x) => x.textContent.trim().startsWith(l) && !x.disabled,
      );
      if (b) {
        b.click();
        return true;
      }
      return false;
    },
    sel,
    label,
  );
  if (!ok) throw new Error(`no enabled ${sel} starting with "${label}"`);
  await sleep(700);
};
const toastText = () =>
  page.$$eval(".toast", (t) => t.map((x) => x.textContent).join(" | "));
async function login(user, pw = password) {
  await page.goto(base);
  await page.waitForSelector("input[name=username]");
  await page.type("input[name=username]", user);
  await page.type("input[name=password]", pw);
  await page.click("button[type=submit]");
  await sleep(1200);
}

// --- auth
await login("a.rivera", crypto.randomBytes(16).toString("hex"));
check("bad password shows an error", (await text("#le"))?.includes("Invalid"));
await page.evaluate(() => {
  document.querySelector("input[name=password]").value = "";
});
await page.type("input[name=password]", password);
await page.click("button[type=submit]");
await sleep(1500);
check(
  "admin signs in and sees the horizontal nav",
  (await count(".tabs a")) === 7,
);

// --- overview range switching
await go("overview");
const before = await text(".k");
await clickText(".seg button", "30d");
check("overview 30d re-queries (value changed)", (await text(".k")) !== before);

// --- alerts
await go("alerts");
const open0 = Number((await text("#tabs .seg .on")).replace(/\D/g, ""));
await clickText("button[data-one=acknowledge]", "Acknowledge");
check(
  "acknowledging an alert gives a toast",
  (await toastText()).includes("acknowledged"),
);
const open1 = Number((await text("#tabs .seg .on")).replace(/\D/g, ""));
check("open count drops by one", open1 === open0 - 1, `${open0} -> ${open1}`);
await page.evaluate(() =>
  document.querySelectorAll("input[data-chk]")[0].click(),
);
await sleep(200);
await page.evaluate(() =>
  document.querySelectorAll("input[data-chk]")[1].click(),
);
await sleep(300);
await clickText("button[data-bulk]", "Resolve");
check("bulk resolve works", (await toastText()).includes("2 alerts updated"));
await page.type("#q", "ssh");
await sleep(800);
check("alert search filters rows", (await count("tbody tr")) >= 1);

// --- events
await go("events");
await page.type("#q", "brute");
await sleep(900);
check("event search narrows results", /events match/.test(await text("#sub")));
await page.click("[data-menu=sev] [data-pop]");
await sleep(200);
await page.click("[data-menu=sev] input[value=critical]");
await sleep(900);
check(
  "severity filter applies",
  await page.$$eval("tbody .b", (b) =>
    b.every((x) => x.textContent.trim() === "Critical"),
  ),
);
await page.evaluate(() => {
  document.activeElement.blur();
  document.body.click();
});
await page.click("tr[data-id]:nth-child(2)");
await sleep(600);
const evtId = await text("#det h3 span");
await clickText("#det button", "Create alert");
check(
  "create alert from event",
  (await toastText()).includes("MANUAL-"),
  evtId,
);
await clickText("#det button", "Block IP");
await clickText(".ov button[type=submit]", "Block IP");
check("block IP confirmation flow", (await toastText()).includes("blocklist"));

// --- decoys
await go("decoys");
const decoys0 = await count("[data-cfg]");
await clickText("button[data-deploy]", "+ Deploy");
await page.type("input[name=name]", "ssh-test-99");
await page.type("input[name=host]", "10.20.9.9");
await clickText(".ov button[type=submit]", "Deploy decoy");
await sleep(500);
check("deploy decoy adds a card", (await count("[data-cfg]")) === decoys0 + 1);
await page.evaluate(() => {
  const c = [...document.querySelectorAll("section.c")].find((s) =>
    s.textContent.includes("ssh-test-99"),
  );
  c.querySelector("[data-toggle]").click();
});
await sleep(700);
check(
  "toggling a decoy pauses it",
  await page.evaluate(() =>
    [...document.querySelectorAll("section.c")]
      .find((s) => s.textContent.includes("ssh-test-99"))
      .textContent.includes("Paused"),
  ),
);
await page.evaluate(() =>
  [...document.querySelectorAll("section.c")]
    .find((s) => s.textContent.includes("ssh-test-99"))
    .querySelector("[data-cfg]")
    .click(),
);
await sleep(400);
await clickText(".ov button", "Delete decoy");
await clickText(".ov:last-of-type button[type=submit]", "Delete");
await sleep(600);
check("delete decoy removes the card", (await count("[data-cfg]")) === decoys0);

// --- rules
await go("rules");
await page.evaluate(() => document.querySelector("[data-f=threshold]").focus());
await page.$eval("[data-f=threshold]", (e) => {
  e.value = "25";
  e.dispatchEvent(new Event("change", { bubbles: true }));
});
await clickText("[data-save]", "Save changes");
check("rule edit saves", (await toastText()).includes("Rule saved"));
await clickText("[data-test]", "Test rule");
check("test rule shows a dry run", (await text(".ov h2"))?.startsWith("Test:"));
await clickText(".ov button", "Close");
await clickText("button[data-new]", "+ New rule");
await page.type("input[name=name]", "E2E rule");
await page.type("input[name=code]", "E2E-01");
await clickText(".ov button[type=submit]", "Create rule");
check(
  "new rule is created",
  await page.evaluate(() => document.body.textContent.includes("E2E rule")),
);

// --- audit & settings
await go("audit");
await clickText("button[data-invite]", "+ Invite");
await page.type("input[name=name]", "E2E User");
await page.type("input[name=username]", "e2e.user");
await clickText(".ov button[type=submit]", "Create user");
check(
  "invite shows a one-time password",
  (await text(".secret code"))?.length > 8,
);
await clickText(".ov button", "Done");
const emailBefore = await page.$eval(
  "[data-set=email_notifications] .tg",
  (e) => e.className,
);
await page.click("[data-set=email_notifications]");
await sleep(700);
check(
  "settings toggle persists",
  (await page.$eval(
    "[data-set=email_notifications] .tg",
    (e) => e.className,
  )) !== emailBefore,
);
check(
  "audit log records the changes",
  await page.evaluate(() => /Invited user/.test(document.body.textContent)),
);

// --- notifications + logout
await page.click("#bell");
await sleep(500);
check("notification list opens", (await count("#notif a")) > 0);
await page.click(".av");
await sleep(200);
await clickText("#umenu .it", "Sign out");
check("sign out returns to login", (await count("input[name=username]")) === 1);

// --- viewer is read only
await login("m.chen");
await go("alerts");
check(
  "viewer sees disabled alert actions",
  await page.evaluate(() =>
    [...document.querySelectorAll("[data-one]")].every((b) => b.disabled),
  ),
);
await go("decoys");
check(
  "viewer cannot deploy decoys",
  await page.$eval("[data-deploy]", (b) => b.disabled),
);

check(
  "no unexpected browser JS errors",
  jsErrors.length === 0,
  jsErrors.slice(0, 3).join(" || "),
);
await browser.close();
console.log(
  failures ? `\n${failures} check(s) failed` : "\nAll end-to-end checks passed",
);
process.exit(failures ? 1 : 0);
