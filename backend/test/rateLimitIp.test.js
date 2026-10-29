const test = require("node:test");
const assert = require("node:assert/strict");

const clientIp = require("../middleware/clientIp");
const rateLimitIp = require("../middleware/rateLimitIp");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const CLOUDFLARE_EDGE = "172.70.1.1";

function reqFrom(peer, headers = {}) {
    const req = mockReq({ headers });
    req.socket = { remoteAddress: peer };
    return req;
}

function call(limiter, req) {
    const res = mockRes();
    let nextCalled = false;
    limiter(req, res, () => { nextCalled = true; });
    return { res, nextCalled };
}

test.beforeEach(() => rateLimitIp._resetAll());

test("clientIp trusts CF-Connecting-IP only from Cloudflare addresses", () => {
    assert.equal(clientIp(reqFrom(CLOUDFLARE_EDGE, { "cf-connecting-ip": "203.0.113.7" })), "203.0.113.7");
    assert.equal(clientIp(reqFrom("::ffff:" + CLOUDFLARE_EDGE, { "cf-connecting-ip": "203.0.113.7" })), "203.0.113.7");
    assert.equal(clientIp(reqFrom("2606:4700::1", { "cf-connecting-ip": "2001:db8::5" })), "2001:db8::5");
});

test("clientIp ignores a spoofed CF-Connecting-IP from a direct connection", () => {
    assert.equal(clientIp(reqFrom("198.51.100.9", { "cf-connecting-ip": "203.0.113.7" })), "198.51.100.9");
    assert.equal(clientIp(reqFrom("::ffff:198.51.100.9")), "198.51.100.9");
});

test("clientIp ignores a malformed CF-Connecting-IP", () => {
    assert.equal(clientIp(reqFrom(CLOUDFLARE_EDGE, { "cf-connecting-ip": "not-an-ip" })), CLOUDFLARE_EDGE);
});

test("login allows 5 attempts per IP, then returns 429 with a retry time", () => {
    const req = () => reqFrom(CLOUDFLARE_EDGE, { "cf-connecting-ip": "203.0.113.7" });
    for (let i = 0; i < 5; i++) assert.equal(call(rateLimitIp.login, req()).nextCalled, true);

    const { res, nextCalled } = call(rateLimitIp.login, req());
    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 429);
    assert.match(res.body.error, /Too many login attempts\. Try again in 30 minutes\./);
    assert.ok(Number(res.headers["Retry-After"]) > 29 * 60);
});

test("visitors behind the same Cloudflare edge get separate budgets", () => {
    for (let i = 0; i <= 5; i++) call(rateLimitIp.login, reqFrom(CLOUDFLARE_EDGE, { "cf-connecting-ip": "203.0.113.7" }));
    assert.equal(call(rateLimitIp.login, reqFrom(CLOUDFLARE_EDGE, { "cf-connecting-ip": "203.0.113.7" })).res.statusCode, 429);
    assert.equal(call(rateLimitIp.login, reqFrom(CLOUDFLARE_EDGE, { "cf-connecting-ip": "203.0.113.8" })).nextCalled, true);
});

test("each form has its own budget", () => {
    for (let i = 0; i <= 5; i++) call(rateLimitIp.login, reqFrom("198.51.100.9"));
    assert.equal(call(rateLimitIp.login, reqFrom("198.51.100.9")).res.statusCode, 429);
    assert.equal(call(rateLimitIp.contact, reqFrom("198.51.100.9")).nextCalled, true);
});

test("the window resets after it expires", (t) => {
    t.mock.timers.enable({ apis: ["Date"], now: 0 });
    const limiter = rateLimitIp.createIpRateLimit({ limit: 1, windowMs: 1000, message: "Slow down." });
    assert.equal(call(limiter, reqFrom("198.51.100.9")).nextCalled, true);
    assert.equal(call(limiter, reqFrom("198.51.100.9")).res.statusCode, 429);
    t.mock.timers.tick(1000);
    assert.equal(call(limiter, reqFrom("198.51.100.9")).nextCalled, true);
});
