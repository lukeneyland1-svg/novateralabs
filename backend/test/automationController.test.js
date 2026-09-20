process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");
const cron = require("node-cron");

const automationController = require("../controllers/automationController");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

// createAutomationTask schedules a real node-cron job on success, which keeps
// a timer alive. Shut every scheduled job down once this file's tests are done
// so the test process can exit.
test.after(() => cron.shutdown());

test("getAutomationTasks returns the seeded tasks newest-first", () => {
    const req = mockReq();
    const res = mockRes();

    automationController.getAutomationTasks(req, res);

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.tasks.length, 2);
    assert.equal(res.body.tasks[0].name, "Site Health Check");
});

test("createAutomationTask rejects a missing name or schedule", () => {
    const req = mockReq({ body: { schedule: "0 2 * * *" } });
    const res = mockRes();

    automationController.createAutomationTask(req, res);

    assert.equal(res.statusCode, 400);
    assert.match(res.body.error, /required/i);
});

test("createAutomationTask rejects an invalid cron expression", () => {
    const req = mockReq({ body: { name: "Bad Task", schedule: "not a cron" } });
    const res = mockRes();

    automationController.createAutomationTask(req, res);

    assert.equal(res.statusCode, 400);
    assert.match(res.body.error, /cron expression/i);
});

test("createAutomationTask inserts and returns the new task", () => {
    const req = mockReq({ body: { name: "Test Task", schedule: "0 3 * * *", type: "health_check" } });
    const res = mockRes();

    automationController.createAutomationTask(req, res);

    assert.equal(res.statusCode, 201);
    assert.equal(res.body.task.name, "Test Task");
    assert.equal(res.body.task.type, "health_check");
    assert.equal(res.body.task.status, "Idle");
});

test("createAutomationTask defaults an unrecognized type to 'log'", () => {
    const req = mockReq({ body: { name: "Default Type Task", schedule: "0 4 * * *", type: "bogus" } });
    const res = mockRes();

    automationController.createAutomationTask(req, res);

    assert.equal(res.statusCode, 201);
    assert.equal(res.body.task.type, "log");
});
