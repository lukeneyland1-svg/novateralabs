process.env.NOVATERALABS_DB_PATH = ":memory:";
process.env.EMAIL_USER = "novateralabs.test@example.com";
process.env.EMAIL_PASS = "test-pass";

const test = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");

const db = require("../db");
const complianceLog = require("../services/complianceLog");
const complianceController = require("../controllers/complianceController");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const userAId = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run("account-a", bcrypt.hashSync("password123", 10)).lastInsertRowid;
const userBId = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run("account-b", bcrypt.hashSync("password456", 10)).lastInsertRowid;

complianceLog.recordEvents(userAId, [
    { source: "linux", severity: "critical", type: "Auth Log", message: "account A's event", ip: "10.0.0.1", timestamp: "2026-01-01T00:00:00.000Z" },
]);
complianceLog.recordEvents(userBId, [
    { source: "linux", severity: "critical", type: "Auth Log", message: "account B's event", ip: "10.0.0.2", timestamp: "2026-01-01T00:00:00.000Z" },
]);

test("exportLog responds with CSV headers and only the requesting account's data", () => {
    const req = mockReq({ session: { userId: userAId }, query: {} });
    const res = mockRes();

    complianceController.exportLog(req, res);

    assert.equal(res.headers["Content-Type"], "text/csv");
    assert.match(res.headers["Content-Disposition"], /attachment/);
    assert.match(res.body, /account A's event/);
    assert.doesNotMatch(res.body, /account B's event/);
});

test("exportLog for a different account returns only that account's data", () => {
    const req = mockReq({ session: { userId: userBId }, query: {} });
    const res = mockRes();

    complianceController.exportLog(req, res);

    assert.match(res.body, /account B's event/);
    assert.doesNotMatch(res.body, /account A's event/);
});
