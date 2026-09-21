process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");

const db = require("../db");
const requireApiKey = require("../middleware/requireApiKey");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const userId = db.prepare("INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)")
    .run("agent-owner", bcrypt.hashSync("password123", 10), "real-api-key").lastInsertRowid;
const ownerId = db.prepare("INSERT INTO users (username, password_hash, api_key, is_owner) VALUES (?, ?, ?, 1)")
    .run("owner-account", bcrypt.hashSync("password123", 10), "owner-api-key").lastInsertRowid;

test("requireApiKey attaches req.apiUserId and calls next() for a valid key", () => {
    const req = mockReq({ headers: { "x-api-key": "real-api-key" } });
    const res = mockRes();
    let nextCalled = false;

    requireApiKey(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, true);
    assert.equal(req.apiUserId, userId);
});

test("requireApiKey sets req.apiIsOwner correctly for an owner's key vs a regular account's key", () => {
    const ownerReq = mockReq({ headers: { "x-api-key": "owner-api-key" } });
    requireApiKey(ownerReq, mockRes(), () => {});
    assert.equal(ownerReq.apiIsOwner, true);

    const regularReq = mockReq({ headers: { "x-api-key": "real-api-key" } });
    requireApiKey(regularReq, mockRes(), () => {});
    assert.equal(regularReq.apiIsOwner, false);
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
