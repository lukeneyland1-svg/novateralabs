process.env.NOVATERALABS_DB_PATH = ":memory:";
process.env.ABUSEIPDB_API_KEY = "test-abuseipdb-key";

const test = require("node:test");
const assert = require("node:assert/strict");

const db = require("../db");
const threatIntel = require("../services/threatIntel");

const originalFetch = global.fetch;
test.after(() => { global.fetch = originalFetch; });

function fakeFetch(impl) {
    global.fetch = impl;
}

function abuseIPDBResponse(score, countryCode = "RU") {
    return {
        ok: true,
        status: 200,
        json: async () => ({ data: { abuseConfidenceScore: score, countryCode } }),
    };
}

test("isPrivateIP classifies common private ranges as private", () => {
    assert.equal(threatIntel.isPrivateIP("10.0.0.5"), true);
    assert.equal(threatIntel.isPrivateIP("192.168.1.1"), true);
    assert.equal(threatIntel.isPrivateIP("172.16.0.1"), true);
    assert.equal(threatIntel.isPrivateIP("172.31.255.255"), true);
    assert.equal(threatIntel.isPrivateIP("127.0.0.1"), true);
    assert.equal(threatIntel.isPrivateIP(null), true);
});

test("isPrivateIP treats a real public IP as not private", () => {
    assert.equal(threatIntel.isPrivateIP("8.8.8.8"), false);
    assert.equal(threatIntel.isPrivateIP("172.32.0.1"), false); // just outside the private 172.16-31 range
});

test("lookupIP never calls fetch for a private IP", async () => {
    let called = false;
    fakeFetch(async () => { called = true; });

    const result = await threatIntel.lookupIP("10.0.0.5");

    assert.equal(called, false);
    assert.equal(result, null);
});

test("lookupIP calls AbuseIPDB for a fresh public IP and caches the result", async () => {
    let callCount = 0;
    fakeFetch(async () => { callCount++; return abuseIPDBResponse(87); });

    const result = await threatIntel.lookupIP("203.0.113.5");

    assert.equal(callCount, 1);
    assert.equal(result.abuseScore, 87);
    assert.equal(result.isMalicious, true);
    assert.equal(result.countryCode, "RU");

    const cached = db.prepare("SELECT * FROM ip_reputation WHERE ip = ?").get("203.0.113.5");
    assert.equal(cached.abuse_score, 87);
});

test("lookupIP uses the cache on a second call instead of calling fetch again", async () => {
    let callCount = 0;
    fakeFetch(async () => { callCount++; return abuseIPDBResponse(1); });

    const result = await threatIntel.lookupIP("203.0.113.5"); // same IP as the previous test

    assert.equal(callCount, 0);
    assert.equal(result.abuseScore, 87); // still the cached value, not the new mock's
});

test("lookupIP scores below the threshold as not malicious", async () => {
    fakeFetch(async () => abuseIPDBResponse(10));

    const result = await threatIntel.lookupIP("203.0.113.9");

    assert.equal(result.isMalicious, false);
});

test("lookupIP falls back gracefully (no throw) when the API call fails", async () => {
    fakeFetch(async () => { throw new Error("network down"); });

    const result = await threatIntel.lookupIP("203.0.113.20");

    assert.equal(result, null); // no prior cache for this IP to fall back to
});

test("lookupIP backs off after a failure instead of retrying every call", async () => {
    // Same IP as the previous test — its failure should already be cached,
    // so a bad/missing key doesn't hammer the real API every 10s refresh.
    let callCount = 0;
    fakeFetch(async () => { callCount++; throw new Error("still down"); });

    const result = await threatIntel.lookupIP("203.0.113.20");

    assert.equal(callCount, 0);
    assert.equal(result, null);
});

test("enrichAlerts looks up each unique IP only once, even if several alerts share it", async () => {
    let callCount = 0;
    fakeFetch(async () => { callCount++; return abuseIPDBResponse(99); });

    const alerts = [
        { ip: "203.0.113.50", message: "a" },
        { ip: "203.0.113.50", message: "b" },
        { ip: "203.0.113.51", message: "c" },
    ];
    const enriched = await threatIntel.enrichAlerts(alerts);

    assert.equal(callCount, 2); // two unique IPs, not three
    assert.equal(enriched[0].reputation.abuseScore, 99);
    assert.equal(enriched[1].reputation.abuseScore, 99);
});

test("enrichAlerts leaves alerts with no IP unenriched", async () => {
    const enriched = await threatIntel.enrichAlerts([{ ip: null, message: "no ip here" }]);
    assert.equal(enriched[0].reputation, null);
});
