const crypto = require("crypto");
const db = require("../db");
const alertNotifier = require("../services/alertNotifier");
const threatIntel = require("../services/threatIntel");
const complianceLog = require("../services/complianceLog");
const cveScanner = require("../services/cveScanner");

exports.reportMetrics = (req, res) => {
    try {
        const { cpu_load, ram_usage, uptime_minutes } = req.body;
        if (typeof cpu_load !== "number" || typeof ram_usage !== "number" || typeof uptime_minutes !== "number") {
            return res.status(400).json({ error: "cpu_load, ram_usage, and uptime_minutes must all be numbers." });
        }

        db.prepare(`
            INSERT INTO metrics_snapshots (user_id, cpu_load, ram_usage, uptime_minutes, reported_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                cpu_load = excluded.cpu_load,
                ram_usage = excluded.ram_usage,
                uptime_minutes = excluded.uptime_minutes,
                reported_at = excluded.reported_at
        `).run(req.apiUserId, cpu_load, ram_usage, uptime_minutes, new Date().toISOString());

        res.json({ success: true });
    } catch (err) {
        console.error("Metrics ingest error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

exports.getMyMetrics = (req, res) => {
    try {
        const snapshot = db.prepare(`
            SELECT cpu_load AS cpuLoad, ram_usage AS ramUsage, uptime_minutes AS uptimeMinutes, reported_at AS reportedAt
            FROM metrics_snapshots WHERE user_id = ?
        `).get(req.session.userId);

        if (!snapshot) {
            return res.json({ received: false });
        }

        res.json({ received: true, ...snapshot });
    } catch (err) {
        console.error("Metrics read error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

const MAX_EVENTS_PER_REPORT = 200;

function isValidEvent(e) {
    return e && typeof e.source === "string" && typeof e.severity === "string" &&
        typeof e.type === "string" && typeof e.message === "string" &&
        typeof e.timestamp === "string" && (e.ip === null || e.ip === undefined || typeof e.ip === "string");
}

const replaceSecurityEvents = db.transaction((userId, events) => {
    db.prepare("DELETE FROM security_events WHERE user_id = ?").run(userId);
    const insert = db.prepare(`
        INSERT INTO security_events (user_id, source, severity, type, message, ip, timestamp, abuse_score, country_code, is_malicious)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const e of events) {
        const rep = e.reputation;
        insert.run(
            userId, e.source, e.severity, e.type, e.message, e.ip || null, e.timestamp,
            rep ? rep.abuseScore : null,
            rep ? rep.countryCode : null,
            rep ? (rep.isMalicious ? 1 : 0) : null
        );
    }
});

exports.reportSecurityEvents = async (req, res) => {
    try {
        const { events } = req.body;
        if (!Array.isArray(events) || events.length > MAX_EVENTS_PER_REPORT) {
            return res.status(400).json({ error: `events must be an array of at most ${MAX_EVENTS_PER_REPORT} items.` });
        }
        if (!events.every(isValidEvent)) {
            return res.status(400).json({ error: "Each event needs source, severity, type, message, and timestamp strings." });
        }

        const enriched = await threatIntel.enrichAlerts(events);
        replaceSecurityEvents(req.apiUserId, enriched);
        complianceLog.recordEvents(req.apiUserId, enriched);
        alertNotifier.checkAndNotifyAccount(req.apiUserId, enriched);

        res.json({ success: true, count: events.length });
    } catch (err) {
        console.error("Security events ingest error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

exports.getMySecurityEvents = (req, res) => {
    try {
        const events = db.prepare(`
            SELECT source, severity, type, message, ip, timestamp,
                   abuse_score AS abuseScore, country_code AS countryCode, is_malicious AS isMalicious
            FROM security_events WHERE user_id = ? ORDER BY timestamp DESC
        `).all(req.session.userId).map(e => ({ ...e, isMalicious: !!e.isMalicious }));

        res.json({ events });
    } catch (err) {
        console.error("Security events read error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

const MAX_PACKAGES_PER_REPORT = 50;
const CVE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;

function isValidPackage(p) {
    return p && typeof p.name === "string" && typeof p.version === "string";
}

// Unlike replaceSecurityEvents above, this is an upsert, not a
// delete-and-reinsert: a CVE finding needs to persist across daily checks
// (first_seen_at stable) so it doesn't re-trigger an alert every single day,
// and only genuinely resolved findings (package upgraded past the vulnerable
// version) get removed. Returns just the newly-inserted findings, since
// those are the only ones that should be alerted on.
const reconcileFindings = db.transaction((userId, findings, now) => {
    const existing = db.prepare(
        "SELECT package_name, cve_id, first_seen_at FROM cve_findings WHERE user_id = ?"
    ).all(userId);
    const existingByKey = new Map(existing.map(r => [`${r.package_name}|${r.cve_id}`, r]));
    const currentKeys = new Set(findings.map(f => `${f.package_name}|${f.cve_id}`));

    const upsert = db.prepare(`
        INSERT INTO cve_findings (user_id, package_name, package_version, cve_id, summary, first_seen_at, last_seen_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, package_name, cve_id) DO UPDATE SET
            package_version = excluded.package_version,
            summary = excluded.summary,
            last_seen_at = excluded.last_seen_at
    `);
    const del = db.prepare("DELETE FROM cve_findings WHERE user_id = ? AND package_name = ? AND cve_id = ?");

    const newFindings = [];
    for (const f of findings) {
        const key = `${f.package_name}|${f.cve_id}`;
        const already = existingByKey.get(key);
        const firstSeenAt = already ? already.first_seen_at : now;
        upsert.run(userId, f.package_name, f.package_version, f.cve_id, f.summary, firstSeenAt, now);
        if (!already) {
            newFindings.push({ ...f, first_seen_at: firstSeenAt });
        }
    }
    for (const row of existing) {
        if (!currentKeys.has(`${row.package_name}|${row.cve_id}`)) {
            del.run(userId, row.package_name, row.cve_id);
        }
    }
    return newFindings;
});

exports.reportPackages = async (req, res) => {
    try {
        const { os, release, packages } = req.body;
        if (typeof os !== "string" || typeof release !== "string" || !Array.isArray(packages) || packages.length > MAX_PACKAGES_PER_REPORT) {
            return res.status(400).json({ error: `os and release must be strings, and packages must be an array of at most ${MAX_PACKAGES_PER_REPORT} items.` });
        }
        if (!packages.every(isValidPackage)) {
            return res.status(400).json({ error: "Each package needs name and version strings." });
        }

        // Rate limit derived from the database, not an in-memory variable --
        // the exact lesson learned from alertNotifier's restart bug earlier
        // today. The agent can report its package list every run cheaply;
        // this is what actually throttles the expensive OSV lookup itself to
        // once per day.
        const user = db.prepare("SELECT last_cve_check_at FROM users WHERE id = ?").get(req.apiUserId);
        const lastCheck = user.last_cve_check_at ? new Date(user.last_cve_check_at).getTime() : 0;
        if (Date.now() - lastCheck < CVE_CHECK_INTERVAL_MS) {
            return res.json({ success: true, checked: false });
        }

        const findings = await cveScanner.checkPackages(os, release, packages);
        const now = new Date().toISOString();
        const newFindings = reconcileFindings(req.apiUserId, findings, now);
        db.prepare("UPDATE users SET last_cve_check_at = ? WHERE id = ?").run(now, req.apiUserId);

        if (newFindings.length > 0) {
            const alerts = newFindings.map(f => ({
                source: "cve-scan",
                severity: "high",
                type: "CVE Finding",
                message: `${f.package_name} ${f.package_version} is vulnerable to ${f.cve_id}${f.summary ? `: ${f.summary}` : ""}`,
                timestamp: f.first_seen_at,
                ip: null,
            }));
            complianceLog.recordEvents(req.apiUserId, alerts);
            // Its own notify path (separate rate-limit clock from security
            // events) -- confirmed via a real end-to-end test that sharing
            // checkAndNotifyAccount's clock let one report starve the other
            // when both arrive from the same agent run moments apart.
            alertNotifier.checkAndNotifyAccountForCve(req.apiUserId, alerts);
        }

        res.json({ success: true, checked: true, findingsCount: findings.length });
    } catch (err) {
        console.error("Package ingest error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

exports.getMyCveFindings = (req, res) => {
    try {
        const findings = db.prepare(`
            SELECT package_name AS packageName, package_version AS packageVersion, cve_id AS cveId,
                   summary, first_seen_at AS firstSeenAt, last_seen_at AS lastSeenAt
            FROM cve_findings WHERE user_id = ? ORDER BY first_seen_at DESC
        `).all(req.session.userId);

        res.json({ findings });
    } catch (err) {
        console.error("CVE findings read error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

exports.getApiKey = (req, res) => {
    const user = db.prepare("SELECT api_key FROM users WHERE id = ?").get(req.session.userId);
    res.json({ apiKey: user.api_key });
};

exports.regenerateApiKey = (req, res) => {
    const newKey = crypto.randomBytes(24).toString("hex");
    db.prepare("UPDATE users SET api_key = ? WHERE id = ?").run(newKey, req.session.userId);
    res.json({ apiKey: newKey });
};
