const db = require("../db");
const { fingerprint } = require("./alertNotifier");

const RETENTION_DAYS = 365; // A reasonable default, not a guarantee of any
                            // specific compliance framework's exact rule —
                            // real requirements vary (SOC 2 ~1yr, HIPAA up to 6yr).

const insert = db.prepare(`
    INSERT OR IGNORE INTO compliance_log (user_id, fingerprint, source, severity, type, message, ip, is_malicious, timestamp, recorded_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

exports.pruneOldEntries = () => {
    const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
    db.prepare("DELETE FROM compliance_log WHERE recorded_at < ?").run(cutoff);
};

exports.recordEvents = (userId, events) => {
    exports.pruneOldEntries();
    const now = new Date().toISOString();
    for (const e of events) {
        const isMalicious = e.reputation ? (e.reputation.isMalicious ? 1 : 0) : null;
        insert.run(userId, fingerprint(e), e.source, e.severity, e.type, e.message, e.ip || null, isMalicious, e.timestamp, now);
    }
};

exports.getComplianceLog = (userId, { from, to } = {}) => {
    let query = "SELECT source, severity, type, message, ip, is_malicious AS isMalicious, timestamp FROM compliance_log WHERE user_id = ?";
    const params = [userId];
    if (from) { query += " AND timestamp >= ?"; params.push(from); }
    if (to) { query += " AND timestamp <= ?"; params.push(to); }
    query += " ORDER BY timestamp ASC";

    return db.prepare(query).all(...params).map(r => ({ ...r, isMalicious: !!r.isMalicious }));
};

function csvEscape(value) {
    const str = value === null || value === undefined ? "" : String(value);
    if (/[",\n]/.test(str)) {
        return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
}

exports.exportAsCSV = (rows) => {
    const header = ["timestamp", "severity", "source", "type", "message", "ip", "isMalicious"];
    const lines = [header.join(",")];
    for (const r of rows) {
        lines.push(header.map(col => csvEscape(r[col])).join(","));
    }
    return lines.join("\n");
};
