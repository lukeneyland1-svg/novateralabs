const test = require("node:test");
const assert = require("node:assert/strict");

const enforceHttps = require("../middleware/enforceHttps");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

test("enforceHttps calls next() when the request is already secure", () => {
    const req = mockReq({});
    req.secure = true;
    const res = mockRes();
    let nextCalled = false;

    enforceHttps(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, true);
    assert.equal(res.redirectedTo, undefined);
});

test("enforceHttps redirects to the https equivalent when the request is plain HTTP", () => {
    const req = mockReq({});
    req.secure = false;
    req.hostname = "novateralabs.com";
    req.originalUrl = "/dashboard.html?foo=bar";
    const res = mockRes();
    let nextCalled = false;

    enforceHttps(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 301);
    assert.equal(res.redirectedTo, "https://novateralabs.com/dashboard.html?foo=bar");
});
