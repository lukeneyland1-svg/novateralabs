const db = require("../db");

const COMPONENTS = ["Website", "Database"];
const CHECK_INTERVAL_MS = 60 * 1000;
const RETENTION_DAYS = 30;

exports.checkWebsite = async () => {
    const start = Date.now();
    try {
        const res = await fetch("https://novateralabs.com", { method: "GET" });
        return { isUp: res.ok, responseTimeMs: Date.now() - start };
    } catch {
        return { isUp: false, responseTimeMs: null };
    }
};

exports.checkDatabase = () => {
    const start = Date.now();
    try {
        db.prepare("SELECT 1").get();
        return { isUp: true, responseTimeMs: Date.now() - start };
    } catch {
        return { isUp: false, responseTimeMs: null };
    }
};

function pruneOldChecks() {
    const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
    db.prepare("DELETE FROM status_checks WHERE checked_at < ?").run(cutoff);
}

exports.runChecks = async () => {
    const [website, database] = await Promise.all([exports.checkWebsite(), exports.checkDatabase()]);
    const now = new Date().toISOString();

    const insert = db.prepare("INSERT INTO status_checks (component, is_up, response_time_ms, checked_at) VALUES (?, ?, ?, ?)");
    insert.run("Website", website.isUp ? 1 : 0, website.responseTimeMs, now);
    insert.run("Database", database.isUp ? 1 : 0, database.responseTimeMs, now);

    pruneOldChecks();
};

exports.getStatusSummary = () => {
    const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();

    const components = COMPONENTS.map((component) => {
        const latest = db.prepare(
            "SELECT is_up, response_time_ms, checked_at FROM status_checks WHERE component = ? ORDER BY checked_at DESC LIMIT 1"
        ).get(component);

        const stats = db.prepare(
            "SELECT COUNT(*) AS total, SUM(is_up) AS upCount FROM status_checks WHERE component = ? AND checked_at >= ?"
        ).get(component, cutoff);

        return {
            name: component,
            isUp: latest ? !!latest.is_up : null,
            responseTimeMs: latest ? latest.response_time_ms : null,
            checkedAt: latest ? latest.checked_at : null,
            uptimePercent: stats.total > 0 ? (stats.upCount / stats.total) * 100 : null,
        };
    });

    const overall = components.every(c => c.isUp !== false) ? "operational" : "degraded";

    return { overall, components };
};

exports.start = () => setInterval(exports.runChecks, CHECK_INTERVAL_MS);
