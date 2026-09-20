process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");
const cron = require("node-cron");

const db = require("../db");
const scheduler = require("../scheduler");

test.after(() => cron.shutdown());

test("scheduleTask refuses an invalid cron expression", () => {
    const scheduled = scheduler.scheduleTask({ id: 999, name: "Bad", schedule: "not a cron" });
    assert.equal(scheduled, false);
});

test("scheduleTask registers a valid cron expression", () => {
    const scheduled = scheduler.scheduleTask({ id: 998, name: "Fine", schedule: "0 0 * * *" });
    assert.equal(scheduled, true);
});

test("executeTask runs a 'log' task and records success on the row", async () => {
    const task = db.prepare("SELECT * FROM automation_tasks WHERE type = 'log'").get();

    await scheduler.executeTask(task);

    const updated = db.prepare("SELECT * FROM automation_tasks WHERE id = ?").get(task.id);
    assert.equal(updated.status, "success");
    assert.match(updated.last_result, /Executed successfully/);
    assert.notEqual(updated.last_run, "—");
});
