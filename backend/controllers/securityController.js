// controllers/securityController.js
const fs   = require("fs/promises");
const path = require("path");
const { EventEmitter } = require("events");
const alertNotifier = require("../services/alertNotifier");

const WINDOWS_ALERTS_PATH = path.join(__dirname, "../data/windows-alerts.json");
const LINUX_LOG_PATHS     = ["/var/log/auth.log", "/var/log/secure"];
const CACHE_TTL           = 10000; // 10 seconds

let cachedAlerts = [];
let lastRead     = 0;

const alertEmitter = new EventEmitter();

// ── Severity classifier for Windows event type string ────────────────────────
function classifyWindowsType(type) {
    if (!type) return "low";
    const t = type.toLowerCase();
    if (t.includes("failed") || t.includes("failure") ||
        t.includes("breach") || t.includes("policy changed")) return "critical";
    if (t.includes("explicit") || t.includes("unauthorized") ||
        t.includes("blocked")  || t.includes("denied"))        return "high";
    if (t.includes("successful logon") || t.includes("sudo") ||
        t.includes("new user") || t.includes("remote"))        return "medium";
    return "low";
}

// ── Severity classifier for Linux auth.log lines ──────────────────────────────
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

// ── Extract first IPv4 address from a string ──────────────────────────────────
function extractIP(str) {
    if (!str) return null;
    const match = str.match(/\b(\d{1,3}\.){3}\d{1,3}\b/);
    return match ? match[0] : null;
}

// ── Parse one raw syslog line ─────────────────────────────────────────────────
// Format: "May 16 09:41:01 hostname process[pid]: message"
function parseLinuxLine(line) {
    if (!line.trim()) return null;
    // The date/time token itself contains colons, so it must be captured as
    // three whitespace-separated fields, not with a colon-excluding class.
    const match = line.match(/^(\S+\s+\S+\s+\S+)\s+(\S+)\s+([^:]+):\s*(.*)$/);
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
// ── Read last ~8KB from Linux auth.log ────────────────────────────────────────
async function readLinuxAlerts() {
    for (const logPath of LINUX_LOG_PATHS) {
        try {
            const fd       = await fs.open(logPath, "r");
            const stats    = await fd.stat();
            const readSize = Math.min(8000, stats.size);
            const buffer   = Buffer.alloc(readSize);
            await fd.read(buffer, 0, readSize, stats.size - readSize);
            await fd.close();

            return buffer.toString()
                .trim()
                .split("\n")
                .map(parseLinuxLine)
                .filter(Boolean)
                .slice(-100)
                .reverse();
        } catch {
            continue;
        }
    }
    console.warn("[security] No readable Linux auth log found.");
    return [];
}

// ── Read Windows alerts JSON (SCP'd from host via PS1 script) ─────────────────
async function readWindowsAlerts() {
    try {
        const raw  = await fs.readFile(WINDOWS_ALERTS_PATH, "utf8");
        const data = JSON.parse(raw);
        const arr  = Array.isArray(data) ? data : [data];

        return arr.map(a => ({
            source:    "windows",
            severity:  classifyWindowsType(a.type),
            type:      a.type      || "Windows Event",
            message:   a.details   || a.message || "No message",
            ip:        a.ip        || extractIP(a.details || "") || null,
            account:   a.account   || null,
            eventId:   a.eventId   || null,
            timestamp: a.timestamp || new Date().toISOString(),
        }));
    } catch (err) {
        if (err.code !== "ENOENT") {
            console.warn("[security] Could not read windows-alerts.json:", err.message);
        }
        return [];
    }
}

// ── Merge, sort, and cache both sources ──────────────────────────────────────
async function refreshCache() {
    const [linux, windows] = await Promise.all([
        readLinuxAlerts(),
        readWindowsAlerts(),
    ]);

    const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

    cachedAlerts = [...linux, ...windows].sort((a, b) => {
        const timeDiff = new Date(b.timestamp) - new Date(a.timestamp);
        if (timeDiff !== 0) return timeDiff;
        return (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4);
    });

    lastRead = Date.now();
    console.log(`[security] Refreshed — ${linux.length} Linux + ${windows.length} Windows alerts`);

    alertEmitter.emit("alerts", cachedAlerts);
    alertNotifier.checkAndNotify(cachedAlerts);
}

// Proactively refresh so alerts are picked up and pushed even with no active pollers/streams.
setInterval(refreshCache, CACHE_TTL);

// ── Route handler: GET /api/security/alerts ───────────────────────────────────
exports.getSecurityEvents = async (req, res) => {
    try {
        if (Date.now() - lastRead > CACHE_TTL) {
            await refreshCache();
        }

        const { severity, source, limit = 100 } = req.query;
        let results = cachedAlerts;

        if (severity) results = results.filter(a => a.severity === severity.toLowerCase());
        if (source)   results = results.filter(a => a.source   === source.toLowerCase());

        res.json(results.slice(0, Number(limit)));
    } catch (err) {
        console.error("[security] API error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

// ── Route handler: GET /api/security/stream ────────────────────────────────────
exports.streamSecurityEvents = (req, res) => {
    res.writeHead(200, {
        "Content-Type":  "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection":    "keep-alive",
    });

    const send = (alerts) => res.write(`data: ${JSON.stringify(alerts)}\n\n`);
    send(cachedAlerts);

    const onAlerts = (alerts) => send(alerts);
    alertEmitter.on("alerts", onAlerts);

    req.on("close", () => alertEmitter.off("alerts", onAlerts));
};

// Test-only seam: exposes the pure parsing/classification helpers plus a way
// to inject a fake cache, so tests don't need real log files or to wait on
// the polling timer above.
exports._test = {
    classifyWindowsType,
    classifyLinuxLine,
    extractIP,
    parseLinuxLine,
    alertEmitter,
    setCache(alerts) {
        cachedAlerts = alerts;
        lastRead = Date.now();
    },
};
