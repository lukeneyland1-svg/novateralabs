const test = require("node:test");
const assert = require("node:assert/strict");
const express = require("express");

const securityHeaders = require("../middleware/securityHeaders");

// Spins up a real HTTP server and hits it with a real fetch, the same
// "assemble the real middleware chain and hit it over the wire" approach
// used elsewhere in this project (e.g. the Stripe webhook middleware-order
// check) rather than trusting helmet's defaults without observing them.
function withTestServer(fn) {
    return new Promise((resolve, reject) => {
        const app = express();
        app.use(securityHeaders);
        app.get("/test", (req, res) => res.send("ok"));

        const server = app.listen(0, async () => {
            try {
                const { port } = server.address();
                await fn(port);
                resolve();
            } catch (err) {
                reject(err);
            } finally {
                server.close();
            }
        });
    });
}

test("sets every header the attack-surface scanner checks for", async () => {
    await withTestServer(async (port) => {
        const res = await fetch(`http://localhost:${port}/test`);
        assert.equal(res.status, 200);

        assert.match(res.headers.get("strict-transport-security"), /max-age=\d+/);
        assert.match(res.headers.get("x-content-type-options"), /nosniff/);
        assert.equal(res.headers.get("x-frame-options"), "DENY");
        assert.equal(res.headers.get("referrer-policy"), "strict-origin-when-cross-origin");
        assert.ok(res.headers.get("content-security-policy"));
    });
});

test("content security policy restricts scripts/frames to same-origin, styles allow inline", async () => {
    await withTestServer(async (port) => {
        const res = await fetch(`http://localhost:${port}/test`);
        const csp = res.headers.get("content-security-policy");

        assert.match(csp, /script-src 'self'/);
        assert.match(csp, /style-src 'self' 'unsafe-inline'/);
        assert.match(csp, /frame-ancestors 'none'/);
        assert.match(csp, /object-src 'none'/);
    });
});
