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
