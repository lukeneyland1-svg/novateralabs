process.env.NOVATERALABS_DB_PATH = ":memory:";
process.env.EMAIL_USER = "novateralabs.test@example.com";
process.env.EMAIL_PASS = "test-pass";

const test = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");

const db = require("../db");
const complianceLog = require("../services/complianceLog");

const userAId = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run("account-a", bcrypt.hashSync("password123", 10)).lastInsertRowid;
const userBId = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run("account-b", bcrypt.hashSync("password456", 10)).lastInsertRowid;

function event(overrides = {}) {
    return {
        source: "linux",
        severity: "critical",
        type: "Auth Log",
        message: "Failed password for root",
        ip: "10.0.0.1",
        timestamp: "2026-01-01T00:00:00.000Z",
        ...overrides,
    };
}

test("recordEvents appends new events", () => {
    complianceLog.recordEvents(userAId, [event({ message: "first event" })]);

    const rows = db.prepare("SELECT message FROM compliance_log WHERE user_id = ?").all(userAId);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].message, "first event");
});

test("recordEvents does not duplicate an identical event reported again (the core behavior this feature depends on)", () => {
    // Same exact event as the previous test — same fingerprint.
    complianceLog.recordEvents(userAId, [event({ message: "first event" })]);
    complianceLog.recordEvents(userAId, [event({ message: "first event" })]);

    const rows = db.prepare("SELECT message FROM compliance_log WHERE user_id = ? AND message = ?").all(userAId, "first event");
    assert.equal(rows.length, 1);
});

test("recordEvents keeps different accounts' identical-looking events fully separate", () => {
    complianceLog.recordEvents(userBId, [event({ message: "first event" })]);

    const aRows = db.prepare("SELECT * FROM compliance_log WHERE user_id = ?").all(userAId);
    const bRows = db.prepare("SELECT * FROM compliance_log WHERE user_id = ?").all(userBId);
    assert.equal(aRows.length, 1);
    assert.equal(bRows.length, 1);
});

test("recordEvents accumulates genuinely different events instead of replacing them", () => {
    complianceLog.recordEvents(userAId, [event({ message: "a second, different event", timestamp: "2026-01-01T00:05:00.000Z" })]);

    const rows = db.prepare("SELECT message FROM compliance_log WHERE user_id = ?").all(userAId);
    assert.equal(rows.length, 2);
});

test("pruneOldEntries removes entries older than the retention window, keeps recent ones", () => {
    const staleDate = new Date(Date.now() - 366 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare(`
        INSERT INTO compliance_log (user_id, fingerprint, source, severity, type, message, ip, is_malicious, timestamp, recorded_at)
        VALUES (?, 'stale-fp', 'linux', 'critical', 'Auth Log', 'stale event', NULL, NULL, ?, ?)
    `).run(userAId, staleDate, staleDate);

    complianceLog.pruneOldEntries();

    const stale = db.prepare("SELECT * FROM compliance_log WHERE fingerprint = 'stale-fp'").all();
    assert.equal(stale.length, 0);
    const recent = db.prepare("SELECT * FROM compliance_log WHERE user_id = ?").all(userAId);
    assert.ok(recent.length >= 2); // the two events from earlier tests survive
});

test("getComplianceLog filters by date range and never returns another account's rows", () => {
    const aLog = complianceLog.getComplianceLog(userAId);
    assert.ok(aLog.every(r => true)); // sanity: doesn't throw, returns an array
    assert.equal(aLog.length, 2);

    const filtered = complianceLog.getComplianceLog(userAId, { from: "2026-01-01T00:04:00.000Z" });
    assert.equal(filtered.length, 1);
    assert.equal(filtered[0].message, "a second, different event");

    const bLog = complianceLog.getComplianceLog(userBId);
    assert.equal(bLog.length, 1);
    assert.ok(!bLog.some(r => r.message === "a second, different event"));
});

test("exportAsCSV correctly escapes a message containing a comma and a quote", () => {
    const csv = complianceLog.exportAsCSV([
        { timestamp: "2026-01-01T00:00:00.000Z", severity: "critical", source: "linux", type: "Auth Log", message: 'Failed for "root", again', ip: "10.0.0.1", isMalicious: false },
    ]);

    const lines = csv.split("\n");
    assert.equal(lines[0], "timestamp,severity,source,type,message,ip,isMalicious");
    assert.ok(lines[1].includes('"Failed for ""root"", again"'));
});

test("exportAsCSV handles an empty result set (just the header row)", () => {
    const csv = complianceLog.exportAsCSV([]);
    assert.equal(csv, "timestamp,severity,source,type,message,ip,isMalicious");
});
