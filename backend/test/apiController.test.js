process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");

const db = require("../db");
const complianceLog = require("../services/complianceLog");
const apiController = require("../controllers/apiController");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const userAId = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run("account-a", bcrypt.hashSync("password123", 10)).lastInsertRowid;
const userBId = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run("account-b", bcrypt.hashSync("password456", 10)).lastInsertRowid;

db.prepare(`
    INSERT INTO metrics_snapshots (user_id, cpu_load, ram_usage, uptime_minutes, reported_at)
    VALUES (?, ?, ?, ?, ?)
`).run(userAId, 12.5, 40.0, 1000, "2026-01-01T00:00:00.000Z");

db.prepare(`
    INSERT INTO security_events (user_id, source, severity, type, message, ip, timestamp)
    VALUES (?, 'linux', 'critical', 'Auth Log', 'account A event', '10.0.0.1', '2026-01-01T00:00:00.000Z')
`).run(userAId);

complianceLog.recordEvents(userAId, [
    { source: "linux", severity: "critical", type: "Auth Log", message: "account A compliance event", ip: "10.0.0.1", timestamp: "2026-01-01T00:00:00.000Z" },
]);

test("getMetrics (API) returns the calling key's own account's data and nothing for another account", () => {
    const reqA = mockReq(); reqA.apiUserId = userAId;
    const resA = mockRes();
    apiController.getMetrics(reqA, resA);
    assert.equal(resA.body.received, true);
    assert.equal(resA.body.cpuLoad, 12.5);

    const reqB = mockReq(); reqB.apiUserId = userBId;
    const resB = mockRes();
    apiController.getMetrics(reqB, resB);
    assert.equal(resB.body.received, false);
});

test("getSecurityEvents (API) returns only the calling key's own account's events", () => {
    const reqA = mockReq(); reqA.apiUserId = userAId;
    const resA = mockRes();
    apiController.getSecurityEvents(reqA, resA);
    assert.equal(resA.body.events.length, 1);
    assert.equal(resA.body.events[0].message, "account A event");

    const reqB = mockReq(); reqB.apiUserId = userBId;
    const resB = mockRes();
    apiController.getSecurityEvents(reqB, resB);
    assert.deepEqual(resB.body.events, []);
});

test("getComplianceLog (API) returns only the calling key's own account's history", () => {
    const reqA = mockReq({ query: {} }); reqA.apiUserId = userAId;
    const resA = mockRes();
    apiController.getComplianceLog(reqA, resA);
    assert.equal(resA.body.events.length, 1);
    assert.equal(resA.body.events[0].message, "account A compliance event");

    const reqB = mockReq({ query: {} }); reqB.apiUserId = userBId;
    const resB = mockRes();
    apiController.getComplianceLog(reqB, resB);
    assert.deepEqual(resB.body.events, []);
});
