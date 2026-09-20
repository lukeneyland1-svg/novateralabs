const crypto = require("crypto");
const db = require("../db");
const { transporter, EMAIL_USER } = require("./mailer");

const RATE_LIMIT_MS = 5 * 60 * 1000;
const PRUNE_AFTER_MS = 7 * 24 * 60 * 60 * 1000;

let lastSentAt = 0;

function fingerprint(alert) {
    return crypto
        .createHash("sha1")
        .update(`${alert.source}|${alert.type}|${alert.message}|${alert.timestamp}`)
        .digest("hex");
}

function pruneOldFingerprints() {
    const cutoff = new Date(Date.now() - PRUNE_AFTER_MS).toISOString();
    db.prepare("DELETE FROM notified_alerts WHERE notified_at < ?").run(cutoff);
}

function formatAlert(alert) {
    const ipPart = alert.ip ? ` (${alert.ip})` : "";
    return `[${alert.severity.toUpperCase()}] ${alert.type} — ${alert.message}${ipPart} — ${alert.timestamp}`;
}

exports.checkAndNotify = async (alerts) => {
    try {
        pruneOldFingerprints();

        const notable = alerts.filter(a => a.severity === "critical" || a.severity === "high");
        if (notable.length === 0) return;

        const alreadyNotified = new Set(
            db.prepare("SELECT fingerprint FROM notified_alerts").all().map(r => r.fingerprint)
        );
        const fresh = notable.filter(a => !alreadyNotified.has(fingerprint(a)));
        if (fresh.length === 0) return;

        if (Date.now() - lastSentAt < RATE_LIMIT_MS) {
            // Skip sending for now; leave these un-marked so they roll into the next digest.
            return;
        }

        const subject = `🚨 ${fresh.length} critical security alert${fresh.length === 1 ? "" : "s"} — NovaTeraLabs`;
        const text = fresh.map(formatAlert).join("\n");

        await transporter.sendMail({
            from: `"NovaTeraLabs Security" <${EMAIL_USER}>`,
            to: EMAIL_USER,
            subject,
            text,
        });

        const insert = db.prepare("INSERT OR IGNORE INTO notified_alerts (fingerprint, notified_at) VALUES (?, ?)");
        const now = new Date().toISOString();
        for (const alert of fresh) insert.run(fingerprint(alert), now);

        lastSentAt = Date.now();
    } catch (err) {
        console.error("[alertNotifier] Failed to send alert digest:", err);
    }
};

// Per-account version of the above, for non-owner accounts' own ingested
// security events. Deliberately kept separate from checkAndNotify/
// notified_alerts/lastSentAt above rather than sharing them — this way a
// change here can't affect the owner's already-working alerting, and two
// unrelated accounts' identically-fingerprinted alerts can't collide.
const lastSentAtByAccount = new Map();

function pruneOldAccountFingerprints(userId) {
    const cutoff = new Date(Date.now() - PRUNE_AFTER_MS).toISOString();
    db.prepare("DELETE FROM account_notified_alerts WHERE user_id = ? AND notified_at < ?").run(userId, cutoff);
}

exports.checkAndNotifyAccount = async (userId, alerts) => {
    try {
        pruneOldAccountFingerprints(userId);

        const notable = alerts.filter(a => a.severity === "critical" || a.severity === "high");
        if (notable.length === 0) return;

        const user = db.prepare("SELECT email FROM users WHERE id = ?").get(userId);
        if (!user || !user.email) return;

        const alreadyNotified = new Set(
            db.prepare("SELECT fingerprint FROM account_notified_alerts WHERE user_id = ?").all(userId).map(r => r.fingerprint)
        );
        const fresh = notable.filter(a => !alreadyNotified.has(fingerprint(a)));
        if (fresh.length === 0) return;

        const lastSent = lastSentAtByAccount.get(userId) || 0;
        if (Date.now() - lastSent < RATE_LIMIT_MS) {
            // Skip sending for now; leave these un-marked so they roll into the next digest.
            return;
        }

        const subject = `🚨 ${fresh.length} critical security alert${fresh.length === 1 ? "" : "s"} — NovaTeraLabs`;
        const text = fresh.map(formatAlert).join("\n");

        await transporter.sendMail({
            from: `"NovaTeraLabs Security" <${EMAIL_USER}>`,
            to: user.email,
            subject,
            text,
        });

        const insert = db.prepare("INSERT OR IGNORE INTO account_notified_alerts (user_id, fingerprint, notified_at) VALUES (?, ?, ?)");
        const now = new Date().toISOString();
        for (const alert of fresh) insert.run(userId, fingerprint(alert), now);

        lastSentAtByAccount.set(userId, Date.now());
    } catch (err) {
        console.error(`[alertNotifier] Failed to send account alert digest for user ${userId}:`, err);
    }
};
