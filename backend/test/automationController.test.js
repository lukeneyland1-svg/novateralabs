process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");
const cron = require("node-cron");
const bcrypt = require("bcryptjs");

const db = require("../db");
const automationController = require("../controllers/automationController");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

// createAutomationTask schedules a real node-cron job on success, which keeps
// a timer alive. Shut every scheduled job down once this file's tests are done
// so the test process can exit.
test.after(() => cron.shutdown());

const ownerId = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run("owner", bcrypt.hashSync("password123", 10)).lastInsertRowid;
// db.js's real backfill only attributes ownerless tasks to a user that
// already existed at module-load time — on a fresh :memory: db (like this
// test's), no user exists yet when the demo tasks are seeded. Simulate what
// actually happens on the server's next boot after an owner account exists.
db.prepare("UPDATE automation_tasks SET user_id = ? WHERE user_id IS NULL").run(ownerId);

const otherUserId = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run("someone-else", bcrypt.hashSync("password456", 10)).lastInsertRowid;

test("getAutomationTasks returns only the current account's tasks, newest-first", () => {
    const req = mockReq({ session: { userId: ownerId } });
    const res = mockRes();

    automationController.getAutomationTasks(req, res);

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.tasks.length, 2);
    assert.equal(res.body.tasks[0].name, "Site Health Check");
});

test("getAutomationTasks never returns another account's tasks", () => {
    const createReq = mockReq({ session: { userId: otherUserId }, body: { name: "Someone Else's Task", schedule: "0 6 * * *" } });
    automationController.createAutomationTask(createReq, mockRes());

    const req = mockReq({ session: { userId: ownerId } });
    const res = mockRes();
    automationController.getAutomationTasks(req, res);

    assert.ok(!res.body.tasks.some(t => t.name === "Someone Else's Task"));
});

test("createAutomationTask rejects a missing name or schedule", () => {
    const req = mockReq({ session: { userId: ownerId }, body: { schedule: "0 2 * * *" } });
    const res = mockRes();

    automationController.createAutomationTask(req, res);

    assert.equal(res.statusCode, 400);
    assert.match(res.body.error, /required/i);
});

test("createAutomationTask rejects an invalid cron expression", () => {
    const req = mockReq({ session: { userId: ownerId }, body: { name: "Bad Task", schedule: "not a cron" } });
    const res = mockRes();

    automationController.createAutomationTask(req, res);

    assert.equal(res.statusCode, 400);
    assert.match(res.body.error, /cron expression/i);
});

test("createAutomationTask inserts and returns the new task, scoped to the current account", () => {
    const req = mockReq({ session: { userId: ownerId }, body: { name: "Test Task", schedule: "0 3 * * *", type: "health_check" } });
    const res = mockRes();

    automationController.createAutomationTask(req, res);

    assert.equal(res.statusCode, 201);
    assert.equal(res.body.task.name, "Test Task");
    assert.equal(res.body.task.type, "health_check");
    assert.equal(res.body.task.status, "Idle");

    const stored = db.prepare("SELECT user_id FROM automation_tasks WHERE id = ?").get(res.body.task.id);
    assert.equal(stored.user_id, ownerId);
});

test("createAutomationTask defaults an unrecognized type to 'log'", () => {
    const req = mockReq({ session: { userId: ownerId }, body: { name: "Default Type Task", schedule: "0 4 * * *", type: "bogus" } });
    const res = mockRes();

    automationController.createAutomationTask(req, res);

    assert.equal(res.statusCode, 201);
    assert.equal(res.body.task.type, "log");
});
