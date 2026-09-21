process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");

const db = require("../db");
const requireSubscription = require("../middleware/requireSubscription");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const ownerId = db.prepare("INSERT INTO users (username, password_hash, is_owner) VALUES (?, ?, 1)")
    .run("owner", bcrypt.hashSync("password123", 10)).lastInsertRowid;
const activeId = db.prepare("INSERT INTO users (username, password_hash, subscription_status) VALUES (?, ?, 'active')")
    .run("paying-customer", bcrypt.hashSync("password123", 10)).lastInsertRowid;
const unpaidId = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run("unpaid-customer", bcrypt.hashSync("password123", 10)).lastInsertRowid;

test("requireSubscription always passes for the owner regardless of subscription status", () => {
    const req = mockReq({ session: { userId: ownerId, isOwner: true } });
    const res = mockRes();
    let nextCalled = false;

    requireSubscription(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, true);
});

test("requireSubscription passes for a non-owner account with an active subscription", () => {
    const req = mockReq({ session: { userId: activeId, isOwner: false } });
    const res = mockRes();
    let nextCalled = false;

    requireSubscription(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, true);
});

test("requireSubscription returns 402 for a non-owner account with no active subscription", () => {
    const req = mockReq({ session: { userId: unpaidId, isOwner: false } });
    const res = mockRes();
    let nextCalled = false;

    requireSubscription(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 402);
});

// ---- Same middleware, now via API-key auth (req.apiUserId/req.apiIsOwner)
// instead of a browser session — this is what the new public API routes use.

test("requireSubscription passes for an owner authenticated via API key", () => {
    const req = mockReq({ session: null });
    req.apiUserId = ownerId;
    req.apiIsOwner = true;
    const res = mockRes();
    let nextCalled = false;

    requireSubscription(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, true);
});

test("requireSubscription passes for a subscribed account authenticated via API key", () => {
    const req = mockReq({ session: null });
    req.apiUserId = activeId;
    req.apiIsOwner = false;
    const res = mockRes();
    let nextCalled = false;

    requireSubscription(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, true);
});

test("requireSubscription returns 402 for an unsubscribed account authenticated via API key", () => {
    const req = mockReq({ session: null });
    req.apiUserId = unpaidId;
    req.apiIsOwner = false;
    const res = mockRes();
    let nextCalled = false;

    requireSubscription(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 402);
});
