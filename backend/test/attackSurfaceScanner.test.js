const test = require("node:test");
const assert = require("node:assert/strict");
const { execSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const tls = require("tls");

const scanner = require("../services/attackSurfaceScanner");

test("isSafeScanTarget rejects localhost (resolves to both ::1 and 127.0.0.1 on this machine)", async () => {
    assert.equal(await scanner.isSafeScanTarget("localhost"), false);
});

test("isSafeScanTarget rejects an unresolvable hostname", async () => {
    assert.equal(await scanner.isSafeScanTarget("this-does-not-exist.invalid"), false);
});

test("isSafeScanTarget accepts a real public hostname", async () => {
    // A well-known, always-public address — not a network call itself (no
    // fetch/tls here), just a DNS lookup to prove the "public passes" path.
    assert.equal(await scanner.isSafeScanTarget("dns.google"), true);
});

// ---- checkSSLCert, against a real local TLS server (not mocked) ----

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scan-test-"));
const keyPath = path.join(tmpDir, "key.pem");
const certPath = path.join(tmpDir, "cert.pem");
execSync(`openssl req -x509 -newkey rsa:2048 -keyout ${keyPath} -out ${certPath} -days 1 -nodes -subj "/CN=localhost"`, { stdio: "ignore" });

const tlsServer = tls.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }, (socket) => socket.end());
let tlsPort;
test.before(() => new Promise((resolve) => {
    tlsServer.listen(0, "127.0.0.1", () => { tlsPort = tlsServer.address().port; resolve(); });
}));
test.after(() => {
    tlsServer.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("checkSSLCert reports a self-signed cert as invalid with the real reason", async () => {
    const result = await scanner.checkSSLCert("127.0.0.1", tlsPort);

    assert.equal(result.available, true);
    assert.equal(result.valid, false);
    assert.equal(result.invalidReason, "DEPTH_ZERO_SELF_SIGNED_CERT");
    assert.equal(typeof result.daysUntilExpiry, "number");
});

test("checkSSLCert reports unavailable when nothing is listening", async () => {
    const result = await scanner.checkSSLCert("127.0.0.1", 1); // port 1: nothing listens here

    assert.equal(result.available, false);
});

// ---- checkSecurityHeaders / checkExposedPaths, mocked fetch ----

const originalFetch = global.fetch;
test.after(() => { global.fetch = originalFetch; });

test("checkSecurityHeaders reports which headers are present vs missing", async () => {
    global.fetch = async () => ({ headers: new Headers({ "strict-transport-security": "max-age=1" }) });

    const result = await scanner.checkSecurityHeaders("https://example.com");

    assert.deepEqual(result.present, ["strict-transport-security"]);
    assert.ok(result.missing.includes("content-security-policy"));
});

test("checkExposedPaths flags a path that responds 200", async () => {
    global.fetch = async (url) => ({ status: url.includes("/.env") ? 200 : 404 });

    const result = await scanner.checkExposedPaths("https://example.com");

    assert.equal(result.inconclusive, false);
    assert.deepEqual(result.exposed, ["/.env"]);
});

test("checkExposedPaths reports inconclusive when the site 200s on everything (SPA catch-all)", async () => {
    global.fetch = async () => ({ status: 200 });

    const result = await scanner.checkExposedPaths("https://example.com");

    assert.equal(result.inconclusive, true);
    assert.deepEqual(result.exposed, []);
});
