const crypto = require("crypto");
const db = require("../db");

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

exports.getApiKey = (req, res) => {
    const user = db.prepare("SELECT api_key FROM users WHERE id = ?").get(req.session.userId);
    res.json({ apiKey: user.api_key });
};

exports.regenerateApiKey = (req, res) => {
    const newKey = crypto.randomBytes(24).toString("hex");
    db.prepare("UPDATE users SET api_key = ? WHERE id = ?").run(newKey, req.session.userId);
    res.json({ apiKey: newKey });
};
