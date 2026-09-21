const crypto = require("crypto");
const db = require("../db");
const alertNotifier = require("../services/alertNotifier");
const threatIntel = require("../services/threatIntel");
const complianceLog = require("../services/complianceLog");

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

exports.getApiKey = (req, res) => {
    const user = db.prepare("SELECT api_key FROM users WHERE id = ?").get(req.session.userId);
    res.json({ apiKey: user.api_key });
};

exports.regenerateApiKey = (req, res) => {
    const newKey = crypto.randomBytes(24).toString("hex");
    db.prepare("UPDATE users SET api_key = ? WHERE id = ?").run(newKey, req.session.userId);
    res.json({ apiKey: newKey });
};
