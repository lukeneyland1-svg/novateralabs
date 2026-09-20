const test = require("node:test");
const assert = require("node:assert/strict");

const requireOwner = require("../middleware/requireOwner");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

test("requireOwner calls next() when session.isOwner is true", () => {
    const req = mockReq({ session: { userId: 1, isOwner: true } });
    const res = mockRes();
    let nextCalled = false;

    requireOwner(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, true);
    assert.equal(res.body, undefined);
});

test("requireOwner returns 403 when session.isOwner is false", () => {
    const req = mockReq({ session: { userId: 2, isOwner: false } });
    const res = mockRes();
    let nextCalled = false;

    requireOwner(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 403);
    assert.deepEqual(res.body, { error: "Not available on this account." });
});

test("requireOwner returns 403 when there is no session", () => {
    const req = mockReq({ session: null });
    const res = mockRes();
    let nextCalled = false;

    requireOwner(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 403);
});
