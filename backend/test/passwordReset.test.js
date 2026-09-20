process.env.NOVATERALABS_DB_PATH = ":memory:";
process.env.EMAIL_USER = "novateralabs.test@example.com";
process.env.EMAIL_PASS = "test-pass";

const test = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");

const db = require("../db");
const mailer = require("../services/mailer");
const authController = require("../controllers/authController");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const originalSendMail = mailer.transporter.sendMail;
test.after(() => { mailer.transporter.sendMail = originalSendMail; });

function fakeSendMail(impl) {
    mailer.transporter.sendMail = impl;
}

db.prepare("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)")
    .run("admin", "admin@example.com", bcrypt.hashSync("old-password", 10));

test("requestPasswordReset gives the same generic response for an unknown email and never emails", async () => {
    let called = false;
    fakeSendMail(async () => { called = true; });

    const req = mockReq({ body: { email: "nobody@example.com" } });
    const res = mockRes();
    await authController.requestPasswordReset(req, res);

    assert.equal(called, false);
    assert.deepEqual(res.body, { success: true, message: "If that email matches an account, a reset link has been sent." });
});

test("requestPasswordReset emails a working reset link for a known email", async () => {
    let sentWith = null;
    fakeSendMail(async (opts) => { sentWith = opts; });

    const req = mockReq({ body: { email: "admin@example.com" } });
    const res = mockRes();
    await authController.requestPasswordReset(req, res);

    assert.deepEqual(res.body, { success: true, message: "If that email matches an account, a reset link has been sent." });
    assert.equal(sentWith.to, "admin@example.com");
    assert.match(sentWith.text, /reset-password\.html\?token=[a-f0-9]{64}/);

    const rows = db.prepare("SELECT * FROM password_resets").all();
    assert.equal(rows.length, 1);
});

test("resetPassword rejects a password shorter than 8 characters", () => {
    const req = mockReq({ body: { token: "whatever", password: "short" } });
    const res = mockRes();
    authController.resetPassword(req, res);
    assert.equal(res.statusCode, 400);
});

test("resetPassword rejects an unknown token", () => {
    const req = mockReq({ body: { token: "not-a-real-token", password: "new-password-123" } });
    const res = mockRes();
    authController.resetPassword(req, res);
    assert.equal(res.statusCode, 400);
});

test("resetPassword rejects an expired token", () => {
    const user = db.prepare("SELECT id FROM users WHERE username = 'admin'").get();
    const expiredToken = "expired-token";
    db.prepare("INSERT INTO password_resets (token, user_id, expires_at) VALUES (?, ?, ?)")
        .run(expiredToken, user.id, new Date(Date.now() - 1000).toISOString());

    const req = mockReq({ body: { token: expiredToken, password: "new-password-123" } });
    const res = mockRes();
    authController.resetPassword(req, res);
    assert.equal(res.statusCode, 400);
});

test("resetPassword succeeds with a fresh token and the token can't be reused", () => {
    const user = db.prepare("SELECT id FROM users WHERE username = 'admin'").get();
    const token = "fresh-token";
    db.prepare("INSERT INTO password_resets (token, user_id, expires_at) VALUES (?, ?, ?)")
        .run(token, user.id, new Date(Date.now() + 60_000).toISOString());

    const req = mockReq({ body: { token, password: "new-password-123" } });
    const res = mockRes();
    authController.resetPassword(req, res);

    assert.deepEqual(res.body, { success: true });
    const updated = db.prepare("SELECT password_hash FROM users WHERE id = ?").get(user.id);
    assert.ok(bcrypt.compareSync("new-password-123", updated.password_hash));

    // Reusing the same token a second time must fail.
    const req2 = mockReq({ body: { token, password: "another-password-456" } });
    const res2 = mockRes();
    authController.resetPassword(req2, res2);
    assert.equal(res2.statusCode, 400);
});
