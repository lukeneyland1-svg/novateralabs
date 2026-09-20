const test = require("node:test");
const assert = require("node:assert/strict");

const requireAuth = require("../middleware/requireAuth");
const requireAuthPage = require("../middleware/requireAuthPage");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

test("requireAuth calls next() when session has a userId", () => {
    const req = mockReq({ session: { userId: 1 } });
    const res = mockRes();
    let nextCalled = false;

    requireAuth(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, true);
    assert.equal(res.body, undefined);
});

test("requireAuth returns 401 when there is no session", () => {
    const req = mockReq({ session: null });
    const res = mockRes();
    let nextCalled = false;

    requireAuth(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 401);
    assert.deepEqual(res.body, { error: "Not authenticated" });
});

test("requireAuth returns 401 when session has no userId", () => {
    const req = mockReq({ session: {} });
    const res = mockRes();
    let nextCalled = false;

    requireAuth(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 401);
});

test("requireAuthPage calls next() when session has a userId", () => {
    const req = mockReq({ session: { userId: 1 } });
    const res = mockRes();
    let nextCalled = false;

    requireAuthPage(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, true);
});

test("requireAuthPage redirects to /login.html when not authenticated", () => {
    const req = mockReq({ session: null });
    const res = mockRes();
    let nextCalled = false;

    requireAuthPage(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 302);
    assert.equal(res.redirectedTo, "/login.html");
});
