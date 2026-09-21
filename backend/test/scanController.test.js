process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");

const db = require("../db");
const scanController = require("../controllers/scanController");
const requireSubscription = require("../middleware/requireSubscription");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const unpaidId = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run("unpaid-customer", bcrypt.hashSync("password123", 10)).lastInsertRowid;

test("the /api/scan route is gated by requireSubscription (402 for a non-owner, non-subscribed account)", () => {
    // This exercises the same requireSubscription middleware the real route
    // uses, confirming it would actually block this account before the
    // controller ever runs — the controller itself doesn't re-check payment.
    const req = mockReq({ session: { userId: unpaidId, isOwner: false } });
    const res = mockRes();
    let nextCalled = false;

    requireSubscription(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 402);
});

test("runScan rejects a target that resolves to a private/loopback address before scanning it", async () => {
    // An IP literal (not "localhost") so this exercises the SSRF-specific
    // guard rather than the earlier, more basic "does this look like a
    // domain at all" shape check — 127.0.0.1 has dots, so it passes that
    // first check and reaches the real DNS-driven safety check.
    const req = mockReq({ session: { userId: unpaidId }, body: { target: "127.0.0.1" } });
    const res = mockRes();

    await scanController.runScan(req, res);

    assert.equal(res.statusCode, 400);
    assert.match(res.body.error, /private|loopback|link-local/i);
});

test("runScan rejects a missing or malformed domain", async () => {
    const req = mockReq({ session: { userId: unpaidId }, body: { target: "" } });
    const res = mockRes();

    await scanController.runScan(req, res);

    assert.equal(res.statusCode, 400);
});

test("getScanTarget stays null when a scan is rejected (nothing should persist)", async () => {
    const before = mockReq({ session: { userId: unpaidId } });
    const beforeRes = mockRes();
    scanController.getScanTarget(before, beforeRes);
    assert.equal(beforeRes.body.target, null);

    // A rejected (unsafe-target) scan shouldn't persist anything.
    const rejected = mockReq({ session: { userId: unpaidId }, body: { target: "127.0.0.1" } });
    await scanController.runScan(rejected, mockRes());

    const stillBefore = mockReq({ session: { userId: unpaidId } });
    const stillBeforeRes = mockRes();
    scanController.getScanTarget(stillBefore, stillBeforeRes);
    assert.equal(stillBeforeRes.body.target, null);
});
