// Checks installed package versions against OSV.dev (Google's open
// vulnerability database) -- no API key, no documented rate limit, verified
// directly against the real API before writing this (both a known-vulnerable
// old Debian package and this exact server's own real packages/OS release).
//
// Debian-family only for now: OSV's Debian ecosystem strings are
// release-qualified ("Debian:11", "Debian:13", ...); Ubuntu additionally
// requires an LTS qualifier and is a deliberate fast-follow, not attempted
// here. Anything else no-ops rather than guessing at an ecosystem string.
//
// Real, verified quirk: Debian OSV entries carry no severity field at all
// (confirmed by inspecting every key on real response objects) -- unlike the
// RubyGems example in OSV's own docs. Every finding is therefore treated as a
// uniform "high" severity by the caller; this service just reports what OSV
// actually returns.
const OSV_QUERY_URL = "https://api.osv.dev/v1/query";

async function checkPackage(ecosystem, name, version) {
    const res = await fetch(OSV_QUERY_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ package: { name, ecosystem }, version }),
    });
    if (!res.ok) {
        throw new Error(`OSV responded ${res.status}`);
    }
    const body = await res.json();
    return body.vulns || [];
}

// Some advisories (Debian security updates especially) don't list an
// upstream CVE at all -- falls back to the advisory's own OSV id so a
// finding is never silently dropped just because it lacks a CVE number.
function extractCveId(vuln) {
    const cve = (vuln.upstream || []).find(id => /^CVE-/.test(id));
    return cve || vuln.id;
}

exports.checkPackages = async (os, release, packages) => {
    if (os !== "debian") {
        return [];
    }
    const ecosystem = `Debian:${release}`;

    const findings = [];
    for (const pkg of packages) {
        try {
            const vulns = await checkPackage(ecosystem, pkg.name, pkg.version);
            for (const vuln of vulns) {
                findings.push({
                    package_name: pkg.name,
                    package_version: pkg.version,
                    cve_id: extractCveId(vuln),
                    summary: vuln.summary || null,
                });
            }
        } catch (err) {
            // One bad response shouldn't abort checking the rest of the list.
            console.error(`[cveScanner] Lookup failed for ${pkg.name} ${pkg.version}:`, err.message);
        }
    }
    return findings;
};
