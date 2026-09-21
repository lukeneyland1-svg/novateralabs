process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");

const db = require("../db");
const statusChecker = require("../services/statusChecker");

const originalFetch = global.fetch;
test.after(() => { global.fetch = originalFetch; });

test("checkDatabase succeeds against a real, live connection", () => {
    const result = statusChecker.checkDatabase();

    assert.equal(result.isUp, true);
    assert.equal(typeof result.responseTimeMs, "number");
});

test("checkWebsite reports up on a successful response", async () => {
    global.fetch = async () => ({ ok: true, status: 200 });

    const result = await statusChecker.checkWebsite();

    assert.equal(result.isUp, true);
    assert.equal(typeof result.responseTimeMs, "number");
});

test("checkWebsite reports down on a non-2xx response", async () => {
    global.fetch = async () => ({ ok: false, status: 503 });

    const result = await statusChecker.checkWebsite();

    assert.equal(result.isUp, false);
});

test("checkWebsite reports down (not throwing) when fetch itself throws", async () => {
    global.fetch = async () => { throw new Error("network down"); };

    const result = await statusChecker.checkWebsite();

    assert.equal(result.isUp, false);
    assert.equal(result.responseTimeMs, null);
});

test("runChecks inserts one row per component", async () => {
    global.fetch = async () => ({ ok: true, status: 200 });

    await statusChecker.runChecks();

    const rows = db.prepare("SELECT component FROM status_checks").all().map(r => r.component);
    assert.ok(rows.includes("Website"));
    assert.ok(rows.includes("Database"));
});

test("runChecks prunes rows older than the 30-day retention window", async () => {
    const staleDate = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare("INSERT INTO status_checks (component, is_up, response_time_ms, checked_at) VALUES (?, ?, ?, ?)")
        .run("Website", 1, 10, staleDate);

    global.fetch = async () => ({ ok: true, status: 200 });
    await statusChecker.runChecks();

    const rows = db.prepare("SELECT checked_at FROM status_checks WHERE checked_at = ?").all(staleDate);
    assert.equal(rows.length, 0);
});

test("getStatusSummary computes uptime percentage and overall status from real history", () => {
    db.prepare("DELETE FROM status_checks").run();

    const now = Date.now();
    const insert = db.prepare("INSERT INTO status_checks (component, is_up, response_time_ms, checked_at) VALUES (?, ?, ?, ?)");
    // Website: 8 up, 2 down => 80% over the window. Database: all up => 100%, but down at the very latest check.
    for (let i = 0; i < 8; i++) insert.run("Website", 1, 50, new Date(now - i * 1000).toISOString());
    for (let i = 8; i < 10; i++) insert.run("Website", 0, null, new Date(now - i * 1000).toISOString());
    for (let i = 0; i < 4; i++) insert.run("Database", 1, 1, new Date(now - (i + 1) * 1000).toISOString());
    insert.run("Database", 0, null, new Date(now).toISOString()); // most recent Database check is down

    const summary = statusChecker.getStatusSummary();

    const website = summary.components.find(c => c.name === "Website");
    const database = summary.components.find(c => c.name === "Database");

    assert.equal(website.isUp, true);
    assert.equal(website.uptimePercent, 80);
    assert.equal(database.isUp, false);
    assert.equal(summary.overall, "degraded"); // Database's latest check is down
});
