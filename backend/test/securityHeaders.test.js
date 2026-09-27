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

// Real production bug: style.css pulls in Google Fonts via @import, which
// was missed the first time by only grepping HTML files for external
// src/href, not the CSS itself — caught by an actual browser CSP violation
// on the live site, not by this test suite. Locking it in now so it can't
// silently regress again.
test("allows Google Fonts, since style.css @imports it", async () => {
    await withTestServer(async (port) => {
        const res = await fetch(`http://localhost:${port}/test`);
        const csp = res.headers.get("content-security-policy");

        assert.match(csp, /style-src[^;]*https:\/\/fonts\.googleapis\.com/);
        assert.match(csp, /font-src[^;]*https:\/\/fonts\.gstatic\.com/);
    });
});

// Cloudflare auto-injects its Web Analytics beacon at the edge, outside this
// codebase entirely — a real production CSP violation caught this one too.
test("allows Cloudflare's auto-injected Web Analytics beacon", async () => {
    await withTestServer(async (port) => {
        const res = await fetch(`http://localhost:${port}/test`);
        const csp = res.headers.get("content-security-policy");

        assert.match(csp, /script-src[^;]*https:\/\/static\.cloudflareinsights\.com/);
    });
});
