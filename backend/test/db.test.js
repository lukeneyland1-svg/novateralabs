process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");

const db = require("../db");

test("creates the expected tables", () => {
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .all()
        .map((r) => r.name);

    assert.ok(tables.includes("automation_tasks"));
    assert.ok(tables.includes("notified_alerts"));
    assert.ok(tables.includes("users"));
});

test("seeds two default automation tasks on a fresh database", () => {
    const rows = db.prepare("SELECT name, type FROM automation_tasks ORDER BY id").all();

    assert.equal(rows.length, 2);
    assert.deepEqual(rows.map((r) => r.name), ["Nightly Backup", "Site Health Check"]);
    assert.deepEqual(rows.map((r) => r.type), ["log", "health_check"]);
});

test("automation_tasks rows have the columns added by the migration", () => {
    const row = db.prepare("SELECT * FROM automation_tasks WHERE name = 'Nightly Backup'").get();

    assert.ok("type" in row);
    assert.ok("last_result" in row);
    assert.equal(row.last_result, "");
});
