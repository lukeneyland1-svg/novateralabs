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

const API_KEY = process.env.NOVATERALABS_API_KEY;
const HOST = "novateralabs.com";
const LINUX_LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"];

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

(async () => {
    const results = await Promise.allSettled([reportMetrics(), reportSecurityEvents()]);
    let failed = false;
    for (const result of results) {
        if (result.status === "rejected") {
            failed = true;
            console.error("Report failed:", result.reason.message);
        }
    }
    process.exit(failed ? 1 : 0);
})();
