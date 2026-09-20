process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");

const db = require("../db");
const requireApiKey = require("../middleware/requireApiKey");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const userId = db.prepare("INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)")
    .run("agent-owner", bcrypt.hashSync("password123", 10), "real-api-key").lastInsertRowid;

test("requireApiKey attaches req.apiUserId and calls next() for a valid key", () => {
    const req = mockReq({ headers: { "x-api-key": "real-api-key" } });
    const res = mockRes();
    let nextCalled = false;

    requireApiKey(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, true);
    assert.equal(req.apiUserId, userId);
});

test("requireApiKey returns 401 when the key is missing", () => {
    const req = mockReq({ headers: {} });
    const res = mockRes();
    let nextCalled = false;

    requireApiKey(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 401);
});

test("requireApiKey returns 401 when the key doesn't match any account", () => {
    const req = mockReq({ headers: { "x-api-key": "not-a-real-key" } });
    const res = mockRes();
    let nextCalled = false;

    requireApiKey(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 401);
});
