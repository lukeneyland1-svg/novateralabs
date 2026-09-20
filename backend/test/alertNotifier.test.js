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
