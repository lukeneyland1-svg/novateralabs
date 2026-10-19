const test = require("node:test");
const assert = require("node:assert/strict");

const rateLimitApiKey = require("../middleware/rateLimitApiKey");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

function call(userId) {
    const req = mockReq();
    req.apiUserId = userId;
    const res = mockRes();
    let nextCalled = false;
    rateLimitApiKey(req, res, () => { nextCalled = true; });
    return { res, nextCalled };
}

test.beforeEach(() => rateLimitApiKey._reset());

test("allows requests up to the limit and reports remaining budget", () => {
    let last;
    for (let i = 0; i < rateLimitApiKey.LIMIT; i++) {
        last = call(1);
        assert.equal(last.nextCalled, true);
    }
    assert.equal(last.res.headers["RateLimit-Limit"], String(rateLimitApiKey.LIMIT));
    assert.equal(last.res.headers["RateLimit-Remaining"], "0");
});

test("returns 429 with Retry-After once the limit is exceeded", () => {
    for (let i = 0; i < rateLimitApiKey.LIMIT; i++) call(1);
    const { res, nextCalled } = call(1);
    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 429);
    assert.ok(Number(res.headers["Retry-After"]) > 0);
});

test("each account has its own independent budget", () => {
    for (let i = 0; i <= rateLimitApiKey.LIMIT; i++) call(1);
    assert.equal(call(1).res.statusCode, 429);
    assert.equal(call(2).nextCalled, true);
});

test("the budget resets after the window passes", (t) => {
    t.mock.timers.enable({ apis: ["Date"] });
    for (let i = 0; i <= rateLimitApiKey.LIMIT; i++) call(1);
    assert.equal(call(1).nextCalled, false);
    t.mock.timers.tick(60 * 1000);
    assert.equal(call(1).nextCalled, true);
});
