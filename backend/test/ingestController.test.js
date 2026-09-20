process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");

const db = require("../db");
const ingestController = require("../controllers/ingestController");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const userAId = db.prepare("INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)")
    .run("account-a", bcrypt.hashSync("password123", 10), "key-a").lastInsertRowid;
const userBId = db.prepare("INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)")
    .run("account-b", bcrypt.hashSync("password456", 10), "key-b").lastInsertRowid;

test("reportMetrics rejects a malformed body", () => {
    const req = mockReq({ body: { cpu_load: "not-a-number", ram_usage: 10, uptime_minutes: 5 } });
    req.apiUserId = userAId;
    const res = mockRes();

    ingestController.reportMetrics(req, res);

    assert.equal(res.statusCode, 400);
});

test("reportMetrics stores a valid report", () => {
    const req = mockReq({ body: { cpu_load: 12.5, ram_usage: 40.2, uptime_minutes: 1000 } });
    req.apiUserId = userAId;
    const res = mockRes();

    ingestController.reportMetrics(req, res);

    assert.deepEqual(res.body, { success: true });
    const row = db.prepare("SELECT * FROM metrics_snapshots WHERE user_id = ?").get(userAId);
    assert.equal(row.cpu_load, 12.5);
    assert.equal(row.ram_usage, 40.2);
});

test("reportMetrics overwrites the previous snapshot instead of duplicating it", () => {
    const req = mockReq({ body: { cpu_load: 99, ram_usage: 88, uptime_minutes: 2000 } });
    req.apiUserId = userAId;
    ingestController.reportMetrics(req, mockRes());

    const rows = db.prepare("SELECT * FROM metrics_snapshots WHERE user_id = ?").all(userAId);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].cpu_load, 99);
});

test("getMyMetrics returns received:false when the account hasn't reported anything", () => {
    const req = mockReq({ session: { userId: userBId } });
    const res = mockRes();

    ingestController.getMyMetrics(req, res);

    assert.deepEqual(res.body, { received: false });
});

test("getMyMetrics returns the current account's own snapshot and never another account's", () => {
    // account-a has a snapshot from the tests above; account-b has none.
    const reqA = mockReq({ session: { userId: userAId } });
    const resA = mockRes();
    ingestController.getMyMetrics(reqA, resA);

    assert.equal(resA.body.received, true);
    assert.equal(resA.body.cpuLoad, 99);

    const reqB = mockReq({ session: { userId: userBId } });
    const resB = mockRes();
    ingestController.getMyMetrics(reqB, resB);

    assert.equal(resB.body.received, false);
});

test("regenerateApiKey changes the stored key and invalidates the old one", () => {
    const oldKey = db.prepare("SELECT api_key FROM users WHERE id = ?").get(userBId).api_key;

    const req = mockReq({ session: { userId: userBId } });
    const res = mockRes();
    ingestController.regenerateApiKey(req, res);

    const newKey = res.body.apiKey;
    assert.notEqual(newKey, oldKey);

    const stored = db.prepare("SELECT api_key FROM users WHERE id = ?").get(userBId).api_key;
    assert.equal(stored, newKey);

    // The old key must no longer resolve to any account.
    const staleOwner = db.prepare("SELECT id FROM users WHERE api_key = ?").get(oldKey);
    assert.equal(staleOwner, undefined);
});

test("getApiKey returns the current account's key", () => {
    const req = mockReq({ session: { userId: userAId } });
    const res = mockRes();

    ingestController.getApiKey(req, res);

    const expected = db.prepare("SELECT api_key FROM users WHERE id = ?").get(userAId).api_key;
    assert.deepEqual(res.body, { apiKey: expected });
});

function event(overrides = {}) {
    return {
        source: "linux",
        severity: "critical",
        type: "Auth Log",
        message: "Failed password for root",
        ip: "10.0.0.1",
        timestamp: "2026-01-01T00:00:00.000Z",
        ...overrides,
    };
}

test("reportSecurityEvents rejects a non-array body", () => {
    const req = mockReq({ body: { events: "not-an-array" } });
    req.apiUserId = userAId;
    const res = mockRes();

    ingestController.reportSecurityEvents(req, res);

    assert.equal(res.statusCode, 400);
});

test("reportSecurityEvents rejects a malformed event", () => {
    const req = mockReq({ body: { events: [{ source: "linux", severity: "critical" }] } });
    req.apiUserId = userAId;
    const res = mockRes();

    ingestController.reportSecurityEvents(req, res);

    assert.equal(res.statusCode, 400);
});

test("reportSecurityEvents rejects an oversized batch", () => {
    const req = mockReq({ body: { events: Array.from({ length: 201 }, () => event()) } });
    req.apiUserId = userAId;
    const res = mockRes();

    ingestController.reportSecurityEvents(req, res);

    assert.equal(res.statusCode, 400);
});

test("reportSecurityEvents stores a valid batch", () => {
    const req = mockReq({ body: { events: [event({ message: "first" }), event({ message: "second" })] } });
    req.apiUserId = userAId;
    const res = mockRes();

    ingestController.reportSecurityEvents(req, res);

    assert.deepEqual(res.body, { success: true, count: 2 });
    const rows = db.prepare("SELECT * FROM security_events WHERE user_id = ?").all(userAId);
    assert.equal(rows.length, 2);
});

test("reportSecurityEvents replaces the previous batch instead of appending to it", () => {
    const req = mockReq({ body: { events: [event({ message: "only this one now" })] } });
    req.apiUserId = userAId;
    ingestController.reportSecurityEvents(req, mockRes());

    const rows = db.prepare("SELECT message FROM security_events WHERE user_id = ?").all(userAId);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].message, "only this one now");
});

test("getMySecurityEvents returns the current account's events and never another account's", () => {
    // account-a has one event from the test above; account-b has none.
    const reqA = mockReq({ session: { userId: userAId } });
    const resA = mockRes();
    ingestController.getMySecurityEvents(reqA, resA);

    assert.equal(resA.body.events.length, 1);
    assert.equal(resA.body.events[0].message, "only this one now");

    const reqB = mockReq({ session: { userId: userBId } });
    const resB = mockRes();
    ingestController.getMySecurityEvents(reqB, resB);

    assert.deepEqual(resB.body.events, []);
});
