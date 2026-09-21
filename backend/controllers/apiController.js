const db = require("../db");
const complianceLog = require("../services/complianceLog");

// Read-only public API (X-API-Key authenticated, see requireApiKey). Kept
// separate from the session-based dashboard controllers rather than making
// those accept either auth method — same principle followed all session:
// don't touch a working, already-tested code path to add an adjacent one.

exports.getMetrics = (req, res) => {
    try {
        const snapshot = db.prepare(`
            SELECT cpu_load AS cpuLoad, ram_usage AS ramUsage, uptime_minutes AS uptimeMinutes, reported_at AS reportedAt
            FROM metrics_snapshots WHERE user_id = ?
        `).get(req.apiUserId);

        if (!snapshot) {
            return res.json({ received: false });
        }
        res.json({ received: true, ...snapshot });
    } catch (err) {
        console.error("API metrics read error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

exports.getSecurityEvents = (req, res) => {
    try {
        const events = db.prepare(`
            SELECT source, severity, type, message, ip, timestamp,
                   abuse_score AS abuseScore, country_code AS countryCode, is_malicious AS isMalicious
            FROM security_events WHERE user_id = ? ORDER BY timestamp DESC
        `).all(req.apiUserId).map(e => ({ ...e, isMalicious: !!e.isMalicious }));

        res.json({ events });
    } catch (err) {
        console.error("API security events read error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

exports.getComplianceLog = (req, res) => {
    try {
        const { from, to } = req.query;
        const events = complianceLog.getComplianceLog(req.apiUserId, { from, to });
        res.json({ events });
    } catch (err) {
        console.error("API compliance log read error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};
