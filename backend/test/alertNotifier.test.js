process.env.NOVATERALABS_DB_PATH = ":memory:";
process.env.EMAIL_USER = "novateralabs.test@example.com";
process.env.EMAIL_PASS = "test-pass";

const test = require("node:test");
const assert = require("node:assert/strict");

const db = require("../db");
const mailer = require("../services/mailer");
const alertNotifier = require("../services/alertNotifier");

const originalSendMail = mailer.transporter.sendMail;
test.after(() => { mailer.transporter.sendMail = originalSendMail; });

function fakeSendMail(impl) {
    mailer.transporter.sendMail = impl;
}

function alert(overrides = {}) {
    return {
        source: "linux",
        type: "Auth Log",
        severity: "critical",
        message: "Failed password for root",
        ip: "10.0.0.1",
        timestamp: "2026-01-01T00:00:00.000Z",
        ...overrides,
    };
}

test("buildDigestText summarizes the count and top repeated source IPs", () => {
    const alerts = [
        alert({ ip: "203.0.113.1", message: "one" }),
        alert({ ip: "203.0.113.1", message: "two" }),
        alert({ ip: "203.0.113.1", message: "three" }),
        alert({ ip: "203.0.113.2", message: "four" }),
    ];

    const text = alertNotifier.buildDigestText(alerts);

    assert.match(text, /^4 new alerts in this digest\./);
    assert.match(text, /Top source IPs: 203\.0\.113\.1 \(3\), 203\.0\.113\.2 \(1\)/);
    assert.match(text, /one/);
    assert.match(text, /four/);
});

test("buildDigestText caps the listed lines and notes the remainder", () => {
    const alerts = Array.from({ length: 55 }, (_, i) => alert({ message: `event-${i}`, timestamp: `2026-01-01T00:${String(i).padStart(2, "0")}:00.000Z` }));

    const text = alertNotifier.buildDigestText(alerts);

    assert.match(text, /event-0\b/);
    assert.doesNotMatch(text, /event-50\b/); // 51st distinct event, past the 50-line cap
    assert.match(text, /… and 5 more\./);
});

// Runs first, while the module-level rate limit is still untouched (lastSentAt
// starts at 0), so this exercises the real send path instead of being skipped.
test("does not throw when the mailer fails to send", async () => {
    fakeSendMail(async () => { throw new Error("smtp down"); });

    const a = alert({ message: "boom" });
    await assert.doesNotReject(() => alertNotifier.checkAndNotify([a]));

    // A failed send is not recorded, so it can be retried on the next pass.
    const rows = db.prepare("SELECT * FROM notified_alerts").all();
    assert.equal(rows.length, 0);
});

test("does nothing when no alerts are critical or high severity", async () => {
    let called = false;
    fakeSendMail(async () => { called = true; });

    await alertNotifier.checkAndNotify([alert({ severity: "medium" }), alert({ severity: "low" })]);

    assert.equal(called, false);
});

test("sends a digest for fresh critical/high alerts and records their fingerprint", async () => {
    let sentWith = null;
    fakeSendMail(async (opts) => { sentWith = opts; });

    const a = alert({ message: "Failed password for admin" });
    await alertNotifier.checkAndNotify([a]);

    assert.ok(sentWith);
    assert.match(sentWith.subject, /1 critical security alert/);
    assert.match(sentWith.text, /Failed password for admin/);

    const rows = db.prepare("SELECT * FROM notified_alerts").all();
    assert.equal(rows.length, 1);
});

test("does not re-notify an alert that was already sent", async () => {
    let called = false;
    fakeSendMail(async () => { called = true; });

    // Same fields as the previous test => same fingerprint => already notified.
    const a = alert({ message: "Failed password for admin" });
    await alertNotifier.checkAndNotify([a]);

    assert.equal(called, false);
});

test("rate-limits sends that happen within the cooldown window", async () => {
    let called = false;
    fakeSendMail(async () => { called = true; });

    const a = alert({ message: "Failed password for someone-else", timestamp: "2026-01-01T00:05:00.000Z" });
    await alertNotifier.checkAndNotify([a]);

    assert.equal(called, false);

    // Not marked as notified, since it was skipped by the rate limit, not sent.
    const rows = db.prepare("SELECT * FROM notified_alerts").all();
    assert.equal(rows.length, 1);
});

test("prunes notified fingerprints older than 7 days", async () => {
    const oldDate = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare("INSERT OR IGNORE INTO notified_alerts (fingerprint, notified_at) VALUES (?, ?)").run("stale-fingerprint", oldDate);

    fakeSendMail(async () => {});
    await alertNotifier.checkAndNotify([]);

    const fingerprints = db.prepare("SELECT fingerprint FROM notified_alerts").all().map(r => r.fingerprint);
    assert.ok(!fingerprints.includes("stale-fingerprint"));
});

// ---- checkAndNotifyAccount (per-account version) ----

const noEmailUserId = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run("no-email-account", "hash").lastInsertRowid;
const accountAId = db.prepare("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)")
    .run("account-a", "hash", "account-a@example.com").lastInsertRowid;
const accountBId = db.prepare("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)")
    .run("account-b", "hash", "account-b@example.com").lastInsertRowid;

test("checkAndNotifyAccount skips sending when the account has no email on file", async () => {
    let called = false;
    fakeSendMail(async () => { called = true; });

    await alertNotifier.checkAndNotifyAccount(noEmailUserId, [alert({ message: "no email on file" })]);

    assert.equal(called, false);
});

test("checkAndNotifyAccount emails the account's own address, not EMAIL_USER", async () => {
    let sentWith = null;
    fakeSendMail(async (opts) => { sentWith = opts; });

    await alertNotifier.checkAndNotifyAccount(accountAId, [alert({ message: "account A's own alert" })]);

    assert.ok(sentWith);
    assert.equal(sentWith.to, "account-a@example.com");
    assert.match(sentWith.text, /account A's own alert/);
});

test("checkAndNotifyAccount does not re-notify the same account for an already-seen fingerprint", async () => {
    let called = false;
    fakeSendMail(async () => { called = true; });

    // Same fields as the previous test => same fingerprint for this account.
    await alertNotifier.checkAndNotifyAccount(accountAId, [alert({ message: "account A's own alert" })]);

    assert.equal(called, false);
});

test("checkAndNotifyAccount keeps separate accounts fully isolated from each other", async () => {
    // Account B has never been notified before, and shares no state with
    // account A above — it must still get its own alert even though A's
    // identical-looking alert was already sent and deduped moments ago.
    let sentWith = null;
    fakeSendMail(async (opts) => { sentWith = opts; });

    await alertNotifier.checkAndNotifyAccount(accountBId, [alert({ message: "account A's own alert" })]);

    assert.ok(sentWith);
    assert.equal(sentWith.to, "account-b@example.com");
});

test("checkAndNotifyAccount rate-limits repeated sends per account within the cooldown", async () => {
    let called = false;
    fakeSendMail(async () => { called = true; });

    // A fresh, distinct alert for account A — not yet notified — but A already
    // sent within the last 5 minutes (the test above), so this must be skipped.
    await alertNotifier.checkAndNotifyAccount(accountAId, [alert({ message: "a brand new alert for A", timestamp: "2026-01-01T00:10:00.000Z" })]);

    assert.equal(called, false);
});

test("checkAndNotifyAccount prunes fingerprints older than 7 days for that account", async () => {
    const oldDate = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare("INSERT OR IGNORE INTO account_notified_alerts (user_id, fingerprint, notified_at) VALUES (?, ?, ?)")
        .run(accountAId, "stale-account-fingerprint", oldDate);

    fakeSendMail(async () => {});
    await alertNotifier.checkAndNotifyAccount(accountAId, []);

    const fingerprints = db.prepare("SELECT fingerprint FROM account_notified_alerts WHERE user_id = ?").all(accountAId).map(r => r.fingerprint);
    assert.ok(!fingerprints.includes("stale-account-fingerprint"));
});
