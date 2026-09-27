const test = require("node:test");
const assert = require("node:assert/strict");

const cveScanner = require("../services/cveScanner");

const originalFetch = global.fetch;
test.after(() => { global.fetch = originalFetch; });

function fakeFetch(impl) {
    global.fetch = impl;
}

function osvResponse(vulns) {
    return { ok: true, status: 200, json: async () => ({ vulns }) };
}

test("checkPackages sends the correct Debian ecosystem string and version", async () => {
    let capturedBody = null;
    fakeFetch(async (url, options) => {
        capturedBody = JSON.parse(options.body);
        return osvResponse([]);
    });

    await cveScanner.checkPackages("debian", "13", [{ name: "openssl", version: "3.5.7-1~deb13u2" }]);

    assert.deepEqual(capturedBody, {
        package: { name: "openssl", ecosystem: "Debian:13" },
        version: "3.5.7-1~deb13u2",
    });
});

test("checkPackages extracts the CVE id from upstream[]", async () => {
    fakeFetch(async () => osvResponse([
        { id: "DLA-3942-1", summary: "openssl - security update", upstream: ["CVE-2023-5678", "DEBIAN-CVE-2023-5678"] },
    ]));

    const findings = await cveScanner.checkPackages("debian", "11", [{ name: "openssl", version: "1.1.1n-0+deb11u3" }]);

    assert.equal(findings.length, 1);
    assert.equal(findings[0].cve_id, "CVE-2023-5678");
    assert.equal(findings[0].package_name, "openssl");
    assert.equal(findings[0].package_version, "1.1.1n-0+deb11u3");
    assert.equal(findings[0].summary, "openssl - security update");
});

test("checkPackages falls back to the OSV advisory id when upstream has no CVE", async () => {
    fakeFetch(async () => osvResponse([{ id: "GHSA-xxxx-yyyy", summary: "no cve listed", upstream: [] }]));

    const findings = await cveScanner.checkPackages("debian", "11", [{ name: "foo", version: "1.0" }]);

    assert.equal(findings[0].cve_id, "GHSA-xxxx-yyyy");
});

test("checkPackages returns an empty array when a package has no vulnerabilities", async () => {
    fakeFetch(async () => osvResponse([]));

    const findings = await cveScanner.checkPackages("debian", "13", [{ name: "bash", version: "5.2.37-2+b10" }]);

    assert.deepEqual(findings, []);
});

test("checkPackages checks multiple packages and aggregates findings across all of them", async () => {
    fakeFetch(async (url, options) => {
        const body = JSON.parse(options.body);
        if (body.package.name === "openssl") return osvResponse([{ id: "DLA-1", summary: "s1", upstream: ["CVE-2024-1"] }]);
        return osvResponse([]);
    });

    const findings = await cveScanner.checkPackages("debian", "11", [
        { name: "openssl", version: "1.1.1n-0+deb11u3" },
        { name: "bash", version: "5.1-2+deb11u1" },
    ]);

    assert.equal(findings.length, 1);
    assert.equal(findings[0].package_name, "openssl");
});

test("checkPackages does not throw when one package's lookup fails, and still checks the rest", async () => {
    fakeFetch(async (url, options) => {
        const body = JSON.parse(options.body);
        if (body.package.name === "openssl") throw new Error("network down");
        return osvResponse([{ id: "DLA-2", summary: "s2", upstream: ["CVE-2024-2"] }]);
    });

    const findings = await cveScanner.checkPackages("debian", "11", [
        { name: "openssl", version: "1.1.1n-0+deb11u3" },
        { name: "bash", version: "5.1-2+deb11u1" },
    ]);

    assert.equal(findings.length, 1);
    assert.equal(findings[0].package_name, "bash");
});

test("checkPackages does not throw when OSV responds with a non-ok status", async () => {
    fakeFetch(async () => ({ ok: false, status: 500 }));

    const findings = await cveScanner.checkPackages("debian", "11", [{ name: "openssl", version: "1.0" }]);

    assert.deepEqual(findings, []);
});

test("checkPackages no-ops entirely for a non-Debian OS, without calling fetch", async () => {
    let called = false;
    fakeFetch(async () => { called = true; return osvResponse([]); });

    const findings = await cveScanner.checkPackages("ubuntu", "22.04", [{ name: "openssl", version: "1.0" }]);

    assert.equal(called, false);
    assert.deepEqual(findings, []);
});
