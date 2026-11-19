import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { startApp } from "./helpers.mjs";

describe("detection engine (PostgreSQL)", () => {
  let app;
  before(async () => {
    app = await startApp({ history: false });
  });
  after(() => app.close());

  const ev = (over = {}) => ({
    decoy: "ssh-dmz-01",
    src_ip: "203.0.113.50",
    type_key: "ssh.brute_force",
    attempts: 30,
    ...over,
  });
  const count = async (sql, ...p) => (await app.db.get(sql, ...p)).c;

  it("raises a critical alert when the SSH brute-force threshold is crossed", async () => {
    const r = await app.engine.ingest(ev());
    assert.equal(r.alerts.length, 1);
    assert.equal(r.alerts[0].severity, "critical");
    assert.match(r.alerts[0].code, /^SSH-BRUTE-01$/);
    assert.equal(
      await count(
        "SELECT COUNT(*) AS c FROM rule_hits WHERE src_ip = ?",
        "203.0.113.50",
      ),
      1,
    );
  });

  it("records further hits but does not duplicate the alert within the cooldown", async () => {
    const r = await app.engine.ingest(
      ev({ src_ip: "203.0.113.51", decoy: "ssh-edge-03" }),
    );
    const r2 = await app.engine.ingest(
      ev({ src_ip: "203.0.113.52", decoy: "ssh-edge-03" }),
    );
    assert.equal(r.alerts.length, 1);
    assert.equal(r2.alerts.length, 0, "same rule+decoy inside cooldown");
    assert.equal(
      await count(
        "SELECT COUNT(*) AS c FROM rule_hits WHERE src_ip = ?",
        "203.0.113.52",
      ),
      1,
    );
  });

  it("creates exactly one alert when many events race (advisory lock)", async () => {
    const results = await Promise.all(
      Array.from({ length: 12 }, (_, i) =>
        app.engine.ingest(
          ev({ src_ip: `198.51.100.${100 + i}`, decoy: "ssh-dmz-02" }),
        ),
      ),
    );
    assert.equal(
      results.reduce((s, r) => s + r.alerts.length, 0),
      1,
    );
  });

  it("does nothing below the threshold", async () => {
    const r = await app.engine.ingest(
      ev({ src_ip: "203.0.113.60", decoy: "ssh-dmz-02", attempts: 5 }),
    );
    assert.equal(r.alerts.length, 0);
    assert.equal(
      await count(
        "SELECT COUNT(*) AS c FROM rule_hits WHERE src_ip = ?",
        "203.0.113.60",
      ),
      0,
    );
  });

  it("aggregates over the rule window (SQL injection needs 3 events)", async () => {
    const e = {
      decoy: "web-admin-02",
      src_ip: "198.51.100.7",
      type_key: "http.sqli",
    };
    assert.equal(
      (await app.engine.ingest({ ...e, attempts: 1 })).alerts.length,
      0,
    );
    assert.equal(
      (await app.engine.ingest({ ...e, attempts: 1 })).alerts.length,
      0,
    );
    assert.equal(
      (await app.engine.ingest({ ...e, attempts: 1 })).alerts.length,
      1,
    );
  });

  it("disabled rules do not fire, and events are flagged as not covered", async () => {
    const before = await count("SELECT COUNT(*) AS c FROM alerts");
    const r = await app.engine.ingest({
      decoy: "ftp-archive-01",
      src_ip: "192.0.2.9",
      type_key: "ftp.anon",
    });
    await app.db.run(
      "UPDATE rules SET enabled = 0 WHERE name = 'Anonymous FTP login'",
    );
    app.engine.invalidateRules();
    const r2 = await app.engine.ingest({
      decoy: "ftp-archive-01",
      src_ip: "192.0.2.10",
      type_key: "ftp.anon",
    });
    assert.equal(r.alerts.length, 1);
    assert.equal(r2.alerts.length, 0);
    assert.equal(
      (
        await app.db.get(
          "SELECT detected FROM events WHERE id = ?",
          r2.event.id,
        )
      ).detected,
      0,
    );
    assert.equal(await count("SELECT COUNT(*) AS c FROM alerts"), before + 1);
  });

  it("rejects invalid input and paused decoys", async () => {
    await assert.rejects(
      app.engine.ingest(ev({ src_ip: "not-an-ip" })),
      /src_ip/,
    );
    await assert.rejects(
      app.engine.ingest(ev({ decoy: "nope" })),
      /Unknown decoy/,
    );
    await assert.rejects(
      app.engine.ingest(ev({ type_key: "Bad Key!" })),
      /type_key/,
    );
    await assert.rejects(app.engine.ingest(ev({ attempts: -3 })), /attempts/);
    await assert.rejects(
      app.engine.ingest(ev({ decoy: "rdp-jump-01" })),
      /disabled/,
    );
    await assert.rejects(
      app.engine.ingest(ev({ ts: Date.now() + 3600e3 })),
      /ts out of range/,
    );
  });

  it("a failed transaction leaves no partial rows behind", async () => {
    const before = await count("SELECT COUNT(*) AS c FROM events");
    await assert.rejects(
      app.db.tx(async () => {
        await app.engine.ingest(
          ev({ src_ip: "203.0.113.77", decoy: "ssh-dmz-02", attempts: 2 }),
        );
        throw new Error("boom");
      }),
      /boom/,
    );
    assert.equal(await count("SELECT COUNT(*) AS c FROM events"), before);
  });

  it("dry-run reports hits without writing anything", async () => {
    const rule = await app.db.get(
      "SELECT * FROM rules WHERE name = 'SSH brute force'",
    );
    const hits = await count("SELECT COUNT(*) AS c FROM rule_hits");
    const alerts = await count("SELECT COUNT(*) AS c FROM alerts");
    const out = await app.engine.dryRun({ ...rule, threshold: 1 });
    assert.ok(out.hits >= 1);
    assert.equal(await count("SELECT COUNT(*) AS c FROM rule_hits"), hits);
    assert.equal(await count("SELECT COUNT(*) AS c FROM alerts"), alerts);
  });
});
