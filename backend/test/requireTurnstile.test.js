const test = require("node:test");
const assert = require("node:assert/strict");

const requireTurnstile = require("../middleware/requireTurnstile");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const realFetch = global.fetch;

async function call(body, { verifyResult, verifyThrows } = {}) {
    let sent;
    global.fetch = async (url, opts) => {
        sent = { url, body: JSON.parse(opts.body) };
        if (verifyThrows) throw new Error("network down");
        return { json: async () => verifyResult };
    };
    const req = mockReq({ body });
    req.socket = { remoteAddress: "198.51.100.9" };
    const res = mockRes();
    let nextCalled = false;
    await requireTurnstile(req, res, () => { nextCalled = true; });
    return { res, nextCalled, sent };
}

test.beforeEach(() => { process.env.TURNSTILE_SECRET_KEY = "test-secret"; });
test.afterEach(() => {
    delete process.env.TURNSTILE_SECRET_KEY;
    global.fetch = realFetch;
});

test("does nothing while no secret key is configured", async () => {
    delete process.env.TURNSTILE_SECRET_KEY;
    const { nextCalled, sent } = await call({});
    assert.equal(nextCalled, true);
    assert.equal(sent, undefined);
});

test("rejects a request with no token without calling Cloudflare", async () => {
    const { res, nextCalled, sent } = await call({});
    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 403);
    assert.equal(sent, undefined);
});

test("passes a token Cloudflare accepts, sending secret, token and visitor IP", async () => {
    const { nextCalled, sent } = await call({ turnstileToken: "good" }, { verifyResult: { success: true } });
    assert.equal(nextCalled, true);
    assert.equal(sent.url, requireTurnstile.VERIFY_URL);
    assert.deepEqual(sent.body, { secret: "test-secret", response: "good", remoteip: "198.51.100.9" });
});

test("rejects a token Cloudflare refuses", async () => {
    const { res, nextCalled } = await call({ turnstileToken: "bad" }, { verifyResult: { success: false, "error-codes": ["invalid-input-response"] } });
    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 403);
    assert.match(res.body.error, /Bot check failed/);
});

test("lets the request through if Cloudflare can't be reached", async (t) => {
    t.mock.method(console, "error", () => {});
    const { nextCalled } = await call({ turnstileToken: "any" }, { verifyThrows: true });
    assert.equal(nextCalled, true);
});
