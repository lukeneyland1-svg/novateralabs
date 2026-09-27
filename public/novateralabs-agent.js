#!/usr/bin/env node
/*
 * NovaTeraLabs agent — reports this machine's CPU/RAM/uptime and recent
 * security-log events to your dashboard. Zero dependencies; only needs
 * Node.js.
 *
 * Setup:
 *   1. Get your API key from the "Connect Your Server" panel on your dashboard.
 *   2. Run it once by hand to check it works:
 *        NOVATERALABS_API_KEY=your-key-here node novateralabs-agent.js
 *   3. Add it to cron to report on a schedule (every minute):
 *        * * * * * NOVATERALABS_API_KEY=your-key-here node /path/to/novateralabs-agent.js
 *
 * Reading the auth log for security events typically needs root or
 * `adm`-group access. If this agent can't read it, it logs a warning and
 * still reports metrics — one failing doesn't block the other.
 */
const os = require("os");
const https = require("https");
const fsp = require("fs/promises");
const { execFile } = require("child_process");
const { promisify } = require("util");
const execFileAsync = promisify(execFile);

const API_KEY = process.env.NOVATERALABS_API_KEY;
const HOST = "novateralabs.com";
const LINUX_LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"];

// A focused, curated set of high-signal, security-relevant packages rather
// than every installed package -- see the dashboard's CVE panel for why.
const CURATED_PACKAGES = [
    "openssh-server", "openssl", "sudo", "curl", "wget", "bash",
    "nginx", "apache2", "mysql-server", "postgresql", "docker.io",
    "python3", "libc6", "systemd",
];

if (!API_KEY) {
    console.error("Missing NOVATERALABS_API_KEY environment variable.");
    process.exit(1);
}

function postJson(pathname, payload) {
    return new Promise((resolve, reject) => {
        const body = JSON.stringify(payload);
        const req = https.request(
            {
                hostname: HOST,
                port: 443,
                path: pathname,
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Content-Length": Buffer.byteLength(body),
                    "X-API-Key": API_KEY,
                },
            },
            (res) => {
                let responseBody = "";
                res.on("data", (chunk) => { responseBody += chunk; });
                res.on("end", () => {
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        resolve(responseBody);
                    } else {
                        reject(new Error(`${res.statusCode}: ${responseBody}`));
                    }
                });
            }
        );
        req.on("error", reject);
        req.write(body);
        req.end();
    });
}

async function reportMetrics() {
    const cpuLoad = Math.min(100, (os.loadavg()[0] / os.cpus().length) * 100);
    const ramUsage = (1 - os.freemem() / os.totalmem()) * 100;
    const uptimeMinutes = os.uptime() / 60;

    await postJson("/api/ingest/metrics", { cpu_load: cpuLoad, ram_usage: ramUsage, uptime_minutes: uptimeMinutes });
    console.log("Metrics reported successfully.");
}

// ── Severity classifier for Linux auth.log lines ──────────────────────────────
// Kept in sync by hand with backend/controllers/securityController.js's
// classifyLinuxLine — this script has to stay a standalone, dependency-free
// file a customer runs on a separate machine, so it can't import that file.
function classifyLinuxLine(line) {
    const l = line.toLowerCase();
    if (l.includes("failed password") || l.includes("authentication failure") ||
        l.includes("invalid user")    || l.includes("too many authentication") ||
        l.includes("possible break-in attempt"))              return "critical";
    if (l.includes("connection closed by") || l.includes("bad protocol") ||
        l.includes("did not receive identification")          ||
        l.includes("unable to negotiate") || l.includes("disconnect") ||
        l.includes("refused connect"))                        return "high";
    if (l.includes("accepted password") || l.includes("accepted publickey") ||
        l.includes("sudo") || l.includes("session opened")   ||
        l.includes("session closed") || l.includes("new user") ||
        l.includes("new group"))                              return "medium";
    return "low";
}

function extractIP(str) {
    if (!str) return null;
    const match = str.match(/\b(\d{1,3}\.){3}\d{1,3}\b/);
    return match ? match[0] : null;
}

// Handles both classic BSD syslog ("May 16 09:41:01 host proc[pid]: msg")
// and modern rsyslog ISO timestamps ("2026-09-20T00:40:48+00:00 host proc[pid]: msg").
// Kept in sync by hand with securityController.js's parseLinuxLine — see the
// note above classifyLinuxLine.
function parseLinuxLine(line) {
    if (!line.trim()) return null;

    let match = line.match(/^(\S+)\s+(\S+)\s+([^:]+):\s*(.*)$/);
    if (match && isNaN(new Date(match[1]).getTime())) {
        match = line.match(/^(\S+\s+\S+\s+\S+)\s+(\S+)\s+([^:]+):\s*(.*)$/);
    }
    if (!match) return null;

    const [, timestampRaw, , , message] = match;
    if (!message) return null;
    const parsed = new Date(timestampRaw);
    const timestamp = isNaN(parsed.getTime()) ? new Date().toISOString() : parsed.toISOString();
    return {
        source: "linux",
        severity: classifyLinuxLine(line),
        type: "Auth Log",
        message,
        ip: extractIP(message),
        timestamp,
    };
}

async function readLinuxEvents() {
    for (const logPath of LINUX_LOG_PATHS) {
        try {
            const handle = await fsp.open(logPath, "r");
            const stats = await handle.stat();
            const readSize = Math.min(8000, stats.size);
            const buffer = Buffer.alloc(readSize);
            await handle.read(buffer, 0, readSize, stats.size - readSize);
            await handle.close();

            return buffer.toString()
                .trim()
                .split("\n")
                .map(parseLinuxLine)
                .filter(Boolean)
                .slice(-100);
        } catch {
            continue;
        }
    }
    return null; // neither log path was readable
}

async function reportSecurityEvents() {
    const events = await readLinuxEvents();
    if (events === null) {
        console.warn("Could not read a security log (checked /var/log/auth.log and /var/log/secure) — skipping this report. This usually needs root or adm-group access.");
        return;
    }

    await postJson("/api/ingest/security-events", { events });
    console.log(`Reported ${events.length} security event(s) successfully.`);
}

// ── Installed-package reporting for CVE scanning ──────────────────────────────
// Debian-family only for now (see backend/services/cveScanner.js for why:
// OSV's Debian ecosystem strings are release-qualified, Ubuntu needs an
// additional LTS qualifier and isn't supported yet). Anything else, this
// quietly skips rather than guessing at an ecosystem string.
async function readOsRelease() {
    try {
        const content = await fsp.readFile("/etc/os-release", "utf8");
        const info = {};
        for (const line of content.split("\n")) {
            const match = line.match(/^([A-Z_]+)=(.*)$/);
            if (match) info[match[1]] = match[2].replace(/^"|"$/g, "");
        }
        return { id: info.ID, versionId: info.VERSION_ID };
    } catch {
        return null;
    }
}

function parsePackageOutput(stdout) {
    return stdout
        .split("\n")
        .filter(Boolean)
        .map((line) => {
            const [name, version] = line.split("\t");
            return name && version ? { name, version } : null;
        })
        .filter(Boolean);
}

async function getInstalledPackages() {
    try {
        const { stdout } = await execFileAsync("dpkg-query", ["-W", "-f=${Package}\t${Version}\n", ...CURATED_PACKAGES]);
        return parsePackageOutput(stdout);
    } catch (err) {
        // dpkg-query exits non-zero whenever ANY requested package isn't
        // installed, even though it still printed the ones it did find to
        // stdout -- verified directly against a real Debian machine before
        // writing this (Node's execFile attaches stdout to the error object
        // even on a non-zero exit, also verified directly rather than
        // assumed). A partial miss here isn't a real failure.
        if (typeof err.stdout === "string") return parsePackageOutput(err.stdout);
        return [];
    }
}

async function reportInstalledPackages() {
    const osRelease = await readOsRelease();
    if (!osRelease || osRelease.id !== "debian") {
        console.log("Skipping CVE package report — this agent only supports Debian-family systems for now.");
        return;
    }

    const packages = await getInstalledPackages();
    if (packages.length === 0) {
        console.log("No curated packages found installed — skipping CVE package report.");
        return;
    }

    await postJson("/api/ingest/packages", { os: "debian", release: osRelease.versionId, packages });
    console.log(`Reported ${packages.length} package(s) for CVE checking.`);
}

(async () => {
    const results = await Promise.allSettled([reportMetrics(), reportSecurityEvents(), reportInstalledPackages()]);
    let failed = false;
    for (const result of results) {
        if (result.status === "rejected") {
            failed = true;
            console.error("Report failed:", result.reason.message);
        }
    }
    process.exit(failed ? 1 : 0);
})();
