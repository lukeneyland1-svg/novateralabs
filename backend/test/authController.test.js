process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const { generateSecret, generate } = require("otplib");

const db = require("../db");
const authController = require("../controllers/authController");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

db.prepare("INSERT INTO users (username, password_hash, is_owner) VALUES (?, ?, 1)")
    .run("admin", bcrypt.hashSync("correct-horse", 10));

const mfaSecret = generateSecret();
const mfaUserId = db.prepare(
    "INSERT INTO users (username, password_hash, totp_secret, totp_enabled, backup_codes) VALUES (?, ?, ?, 1, ?)"
).run(
    "mfa-admin",
    bcrypt.hashSync("correct-horse", 10),
    mfaSecret,
    JSON.stringify([bcrypt.hashSync("BACKUP1234", 10)])
).lastInsertRowid;

test("login rejects a request missing username or password", () => {
    const req = mockReq({ body: { username: "admin" } });
    const res = mockRes();

    authController.login(req, res);

    assert.equal(res.statusCode, 400);
});

test("login rejects an unknown username", () => {
    const req = mockReq({ body: { username: "nobody", password: "whatever" }, session: {} });
    const res = mockRes();

    authController.login(req, res);

    assert.equal(res.statusCode, 401);
    assert.deepEqual(res.body, { error: "Invalid username or password" });
});

test("login rejects the wrong password", () => {
    const req = mockReq({ body: { username: "admin", password: "wrong-password" }, session: {} });
    const res = mockRes();

    authController.login(req, res);

    assert.equal(res.statusCode, 401);
});

test("login succeeds with the right credentials and starts a session", () => {
    const session = {};
    const req = mockReq({ body: { username: "admin", password: "correct-horse" }, session });
    const res = mockRes();

    authController.login(req, res);

    assert.deepEqual(res.body, { success: true, username: "admin" });
    assert.equal(session.userId, db.prepare("SELECT id FROM users WHERE username = 'admin'").get().id);
    assert.equal(session.username, "admin");
    assert.equal(session.isOwner, true);
});

test("login responds mfaRequired for an MFA-enabled account instead of starting a full session", () => {
    const session = {};
    const req = mockReq({ body: { username: "mfa-admin", password: "correct-horse" }, session });
    const res = mockRes();

    authController.login(req, res);

    assert.deepEqual(res.body, { mfaRequired: true });
    assert.equal(session.pendingMfaUserId, mfaUserId);
    assert.equal(session.userId, undefined);
});

test("verifyMfaLogin rejects when there is no pending MFA login", async () => {
    const req = mockReq({ body: { code: "123456" }, session: {} });
    const res = mockRes();

    await authController.verifyMfaLogin(req, res);

    assert.equal(res.statusCode, 400);
});

test("verifyMfaLogin rejects an incorrect code", async () => {
    const req = mockReq({ body: { code: "000000" }, session: { pendingMfaUserId: mfaUserId } });
    const res = mockRes();

    await authController.verifyMfaLogin(req, res);

    assert.equal(res.statusCode, 401);
});

test("verifyMfaLogin promotes the session on a correct TOTP code", async () => {
    const code = await generate({ secret: mfaSecret });
    const session = { pendingMfaUserId: mfaUserId };
    const req = mockReq({ body: { code }, session });
    const res = mockRes();

    await authController.verifyMfaLogin(req, res);

    assert.deepEqual(res.body, { success: true, username: "mfa-admin" });
    assert.equal(session.userId, mfaUserId);
    assert.equal(session.pendingMfaUserId, undefined);
    // mfa-admin was created without is_owner set, so it defaults to a
    // regular (non-owner) provisioned account.
    assert.equal(session.isOwner, false);
});

test("verifyMfaLogin accepts a valid backup code and burns it after one use", async () => {
    const firstReq = mockReq({ body: { code: "BACKUP1234" }, session: { pendingMfaUserId: mfaUserId } });
    const firstRes = mockRes();
    await authController.verifyMfaLogin(firstReq, firstRes);
    assert.equal(firstRes.body.success, true);

    const secondReq = mockReq({ body: { code: "BACKUP1234" }, session: { pendingMfaUserId: mfaUserId } });
    const secondRes = mockRes();
    await authController.verifyMfaLogin(secondReq, secondRes);
    assert.equal(secondRes.statusCode, 401);
});

test("logout destroys the session and clears the cookie", () => {
    const req = mockReq({ session: {} });
    const res = mockRes();

    authController.logout(req, res);

    assert.equal(res.clearedCookie, "connect.sid");
    assert.deepEqual(res.body, { success: true });
});

test("checkSession reports authenticated when a session has a userId", () => {
    const req = mockReq({ session: { userId: 1, username: "admin", isOwner: true } });
    const res = mockRes();

    authController.checkSession(req, res);

    assert.deepEqual(res.body, { authenticated: true, username: "admin", mfaEnabled: false, isOwner: true });
});

test("checkSession reports unauthenticated with no session", () => {
    const req = mockReq({ session: null });
    const res = mockRes();

    authController.checkSession(req, res);

    assert.equal(res.statusCode, 401);
    assert.deepEqual(res.body, { authenticated: false });
});
