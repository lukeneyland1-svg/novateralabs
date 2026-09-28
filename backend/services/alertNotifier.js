const crypto = require("crypto");
const db = require("../db");
const { transporter, EMAIL_USER } = require("./mailer");
const webhookNotifier = require("./webhookNotifier");

// Was 5 minutes, then 1 hour, then 6 hours — a public server's SSH port gets
// constant background scanning from bots across the internet, and every
// attempt has a distinct timestamp (so a distinct fingerprint), so even the
// 1-hour window meant a digest fired roughly every hour, around the clock.
// 4 hours (~6/day) is the user's own preferred balance between inbox volume
// and how stale a real event's notification can get — every event is still
// recorded immediately on the dashboard and in the compliance log regardless
// of digest timing either way; this only delays the notification, not the
// record.
const RATE_LIMIT_MS = 4 * 60 * 60 * 1000;
const PRUNE_AFTER_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_LISTED_ALERTS = 50;

// Derived from the table itself rather than kept in a variable: an in-memory
// value forgets on every process restart, which happens often enough during
// active development that it was silently defeating the rate limit entirely
// (each restart reset the clock to zero, forcing an immediate send). Every
// row already carries the exact instant it was sent, so the most recent one
// IS "last sent" — no separate state to fall out of sync.
function getLastSentAt() {
    const row = db.prepare("SELECT MAX(notified_at) AS lastSentAt FROM notified_alerts").get();
    return row.lastSentAt ? new Date(row.lastSentAt).getTime() : 0;
}

function fingerprint(alert) {
    return crypto
        .createHash("sha1")
        .update(`${alert.source}|${alert.type}|${alert.message}|${alert.timestamp}`)
        .digest("hex");
}
exports.fingerprint = fingerprint;

function pruneOldFingerprints() {
    const cutoff = new Date(Date.now() - PRUNE_AFTER_MS).toISOString();
    db.prepare("DELETE FROM notified_alerts WHERE notified_at < ?").run(cutoff);
}

function formatAlert(alert) {
    const ipPart = alert.ip ? ` (${alert.ip})` : "";
    return `[${alert.severity.toUpperCase()}] ${alert.type} — ${alert.message}${ipPart} — ${alert.timestamp}`;
}

// A flat list of every alert stops being useful once a digest covers a full
// hour instead of 5 minutes — this adds a count + "top offending IPs"
// summary above the per-alert lines, and caps how many individual lines get
// listed so a genuine flood doesn't produce an absurdly long message.
function buildDigestText(alerts) {
    const ipCounts = new Map();
    for (const a of alerts) {
        if (a.ip) ipCounts.set(a.ip, (ipCounts.get(a.ip) || 0) + 1);
    }
    const topIPs = [...ipCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);

    const lines = [`${alerts.length} new alert${alerts.length === 1 ? "" : "s"} in this digest.`];
    if (topIPs.length > 0) {
        lines.push("Top source IPs: " + topIPs.map(([ip, count]) => `${ip} (${count})`).join(", "));
    }
    lines.push("");
    lines.push(...alerts.slice(0, MAX_LISTED_ALERTS).map(formatAlert));
    if (alerts.length > MAX_LISTED_ALERTS) {
        lines.push(`… and ${alerts.length - MAX_LISTED_ALERTS} more.`);
    }
    return lines.join("\n");
}
exports.buildDigestText = buildDigestText;

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

        if (Date.now() - getLastSentAt() < RATE_LIMIT_MS) {
            // Skip sending for now; leave these un-marked so they roll into the next digest.
            return;
        }

        const subject = `🚨 ${fresh.length} critical security alert${fresh.length === 1 ? "" : "s"} — NovaTeraLabs`;
        const text = buildDigestText(fresh);

        await transporter.sendMail({
            from: `"NovaTeraLabs Security" <${EMAIL_USER}>`,
            to: EMAIL_USER,
            subject,
            text,
        });
        webhookNotifier.sendToWebhook(`*${subject}*\n${text}`);

        const insert = db.prepare("INSERT OR IGNORE INTO notified_alerts (fingerprint, notified_at) VALUES (?, ?)");
        const now = new Date().toISOString();
        for (const alert of fresh) insert.run(fingerprint(alert), now);
    } catch (err) {
        console.error("[alertNotifier] Failed to send alert digest:", err);
    }
};

// Per-account version of the above, for non-owner accounts' own ingested
// security events. Deliberately kept separate from checkAndNotify/
// notified_alerts above rather than sharing them — this way a change here
// can't affect the owner's already-working alerting, and two unrelated
// accounts' identically-fingerprinted alerts can't collide.
function getLastSentAtForAccount(userId) {
    const row = db.prepare("SELECT MAX(notified_at) AS lastSentAt FROM account_notified_alerts WHERE user_id = ?").get(userId);
    return row.lastSentAt ? new Date(row.lastSentAt).getTime() : 0;
}

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

        if (Date.now() - getLastSentAtForAccount(userId) < RATE_LIMIT_MS) {
            // Skip sending for now; leave these un-marked so they roll into the next digest.
            return;
        }

        const subject = `🚨 ${fresh.length} critical security alert${fresh.length === 1 ? "" : "s"} — NovaTeraLabs`;
        const text = buildDigestText(fresh);

        await transporter.sendMail({
            from: `"NovaTeraLabs Security" <${EMAIL_USER}>`,
            to: user.email,
            subject,
            text,
        });

        const insert = db.prepare("INSERT OR IGNORE INTO account_notified_alerts (user_id, fingerprint, notified_at) VALUES (?, ?, ?)");
        const now = new Date().toISOString();
        for (const alert of fresh) insert.run(userId, fingerprint(alert), now);
    } catch (err) {
        console.error(`[alertNotifier] Failed to send account alert digest for user ${userId}:`, err);
    }
};

// CVE-finding version of the above. Deliberately its own table/rate-limit
// clock, not shared with checkAndNotifyAccount -- a real end-to-end test of
// the CVE scanner caught that sharing one clock meant whichever report (auth-
// log security events or CVE findings) happened to reach the server first
// would "use up" the account's cooldown and silently starve the other, since
// both usually arrive from the same agent run moments apart. This is the
// exact same reasoning as keeping this file's owner-path and account-path
// state separate above, applied one level deeper.
function getLastSentAtForAccountCve(userId) {
    const row = db.prepare("SELECT MAX(notified_at) AS lastSentAt FROM account_notified_cve_alerts WHERE user_id = ?").get(userId);
    return row.lastSentAt ? new Date(row.lastSentAt).getTime() : 0;
}

function pruneOldAccountCveFingerprints(userId) {
    const cutoff = new Date(Date.now() - PRUNE_AFTER_MS).toISOString();
    db.prepare("DELETE FROM account_notified_cve_alerts WHERE user_id = ? AND notified_at < ?").run(userId, cutoff);
}

exports.checkAndNotifyAccountForCve = async (userId, alerts) => {
    try {
        pruneOldAccountCveFingerprints(userId);

        const notable = alerts.filter(a => a.severity === "critical" || a.severity === "high");
        if (notable.length === 0) return;

        const user = db.prepare("SELECT email FROM users WHERE id = ?").get(userId);
        if (!user || !user.email) return;

        const alreadyNotified = new Set(
            db.prepare("SELECT fingerprint FROM account_notified_cve_alerts WHERE user_id = ?").all(userId).map(r => r.fingerprint)
        );
        const fresh = notable.filter(a => !alreadyNotified.has(fingerprint(a)));
        if (fresh.length === 0) return;

        if (Date.now() - getLastSentAtForAccountCve(userId) < RATE_LIMIT_MS) {
            return;
        }

        const subject = `🚨 ${fresh.length} critical security alert${fresh.length === 1 ? "" : "s"} — NovaTeraLabs`;
        const text = buildDigestText(fresh);

        await transporter.sendMail({
            from: `"NovaTeraLabs Security" <${EMAIL_USER}>`,
            to: user.email,
            subject,
            text,
        });

        const insert = db.prepare("INSERT OR IGNORE INTO account_notified_cve_alerts (user_id, fingerprint, notified_at) VALUES (?, ?, ?)");
        const now = new Date().toISOString();
        for (const alert of fresh) insert.run(userId, fingerprint(alert), now);
    } catch (err) {
        console.error(`[alertNotifier] Failed to send account CVE alert digest for user ${userId}:`, err);
    }
};
