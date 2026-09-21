const dns = require("dns");
const tls = require("tls");
const crypto = require("crypto");

const SECURITY_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"];
const EXPOSED_PATHS = ["/.env", "/.git/config", "/wp-admin", "/phpmyadmin", "/.aws/credentials", "/config.php"];
const FETCH_TIMEOUT_MS = 8000;

// SSRF guard: rejects a resolved address that's private/loopback/link-local
// (the last of which covers 169.254.169.254, the cloud metadata endpoint
// most VMs expose). Checks EVERY address a hostname resolves to, not just
// the first — a hostname can have both a public and a private/loopback
// record (confirmed by testing "localhost", which resolves to both ::1 and
// 127.0.0.1 on this machine).
function isPrivateAddress(address, family) {
    if (family === 4) {
        return /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(address);
    }
    const a = address.toLowerCase();
    return a === "::1" || a.startsWith("fe80:") || a.startsWith("fc") || a.startsWith("fd");
}

async function isSafeScanTarget(hostname) {
    let addresses;
    try {
        addresses = await dns.promises.lookup(hostname, { all: true });
    } catch {
        return false; // doesn't resolve at all — nothing safe to scan
    }
    if (addresses.length === 0) return false;
    return addresses.every(a => !isPrivateAddress(a.address, a.family));
}
exports.isSafeScanTarget = isSafeScanTarget;

function fetchWithTimeout(url, options = {}) {
    return fetch(url, { ...options, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
}

exports.checkSSLCert = (hostname, port = 443) => {
    return new Promise((resolve) => {
        const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: FETCH_TIMEOUT_MS }, () => {
            const cert = socket.getPeerCertificate();
            const daysUntilExpiry = cert.valid_to ? Math.round((new Date(cert.valid_to) - Date.now()) / (1000 * 60 * 60 * 24)) : null;
            socket.end();
            resolve({
                available: true,
                valid: socket.authorized,
                invalidReason: socket.authorized ? null : socket.authorizationError,
                issuer: cert.issuer ? cert.issuer.CN || null : null,
                daysUntilExpiry,
            });
        });
        socket.on("error", () => resolve({ available: false }));
        socket.on("timeout", () => { socket.destroy(); resolve({ available: false }); });
    });
};

exports.checkSecurityHeaders = async (url) => {
    const res = await fetchWithTimeout(url);
    const missing = SECURITY_HEADERS.filter(h => !res.headers.has(h));
    return { present: SECURITY_HEADERS.filter(h => res.headers.has(h)), missing };
};

exports.checkExposedPaths = async (baseUrl) => {
    // Control request first: some sites (SPA catch-all routing) return 200
    // for literally any path, which would otherwise flag every path below
    // as "exposed" — a real false-positive case, not a hypothetical one.
    const controlPath = `/__scan-control-${crypto.randomBytes(6).toString("hex")}`;
    const controlRes = await fetchWithTimeout(new URL(controlPath, baseUrl).toString());
    if (controlRes.status === 200) {
        return { inconclusive: true, exposed: [] };
    }

    const exposed = [];
    for (const path of EXPOSED_PATHS) {
        try {
            const res = await fetchWithTimeout(new URL(path, baseUrl).toString());
            if (res.status === 200) exposed.push(path);
        } catch {
            // Unreachable path — not exposed, just skip it.
        }
    }
    return { inconclusive: false, exposed };
};

exports.runScan = async (target) => {
    const url = target.startsWith("http") ? target : `https://${target}`;
    const hostname = new URL(url).hostname;

    if (!(await isSafeScanTarget(hostname))) {
        const err = new Error("That target resolves to a private, loopback, or link-local address and can't be scanned.");
        err.code = "UNSAFE_TARGET";
        throw err;
    }

    const [ssl, headers, paths] = await Promise.all([
        exports.checkSSLCert(hostname).catch(() => ({ available: false })),
        exports.checkSecurityHeaders(url).catch(() => null),
        exports.checkExposedPaths(url).catch(() => null),
    ]);

    return { target: hostname, ssl, headers, paths };
};
