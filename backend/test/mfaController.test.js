process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const { generate } = require("otplib");

const db = require("../db");
const mfaController = require("../controllers/mfaController");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const userId = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run("admin", bcrypt.hashSync("correct-horse", 10)).lastInsertRowid;

test("setupMfa generates and stores a secret without enabling MFA yet", async () => {
    const req = mockReq({ session: { userId } });
    const res = mockRes();

    await mfaController.setupMfa(req, res);

    assert.equal(typeof res.body.secret, "string");
    assert.match(res.body.qrCode, /^data:image\/png;base64,/);

    const user = db.prepare("SELECT totp_secret, totp_enabled FROM users WHERE id = ?").get(userId);
    assert.equal(user.totp_secret, res.body.secret);
    assert.equal(user.totp_enabled, 0);
});

test("confirmMfa rejects an incorrect code and leaves MFA disabled", async () => {
    const req = mockReq({ session: { userId }, body: { code: "000000" } });
    const res = mockRes();

    await mfaController.confirmMfa(req, res);

    assert.equal(res.statusCode, 400);
    const user = db.prepare("SELECT totp_enabled FROM users WHERE id = ?").get(userId);
    assert.equal(user.totp_enabled, 0);
});

test("confirmMfa rejects a malformed (non-6-digit) code with 400, not a crash", async () => {
    // otplib's verify() throws on a token that isn't 6 digits — this must be
    // treated as an ordinary invalid code, not surfaced as a 500.
    const req = mockReq({ session: { userId }, body: { code: "not-a-code" } });
    const res = mockRes();

    await mfaController.confirmMfa(req, res);

    assert.equal(res.statusCode, 400);
});

test("confirmMfa enables MFA and issues 10 one-time backup codes for a correct code", async () => {
    const { totp_secret } = db.prepare("SELECT totp_secret FROM users WHERE id = ?").get(userId);
    const code = await generate({ secret: totp_secret });

    const req = mockReq({ session: { userId }, body: { code } });
    const res = mockRes();
    await mfaController.confirmMfa(req, res);

    assert.equal(res.body.success, true);
    assert.equal(res.body.backupCodes.length, 10);

    const user = db.prepare("SELECT totp_enabled, backup_codes FROM users WHERE id = ?").get(userId);
    assert.equal(user.totp_enabled, 1);
    assert.equal(JSON.parse(user.backup_codes).length, 10);
});

test("verifyAndConsumeBackupCode accepts a real backup code exactly once", () => {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    const hashedCodes = JSON.parse(user.backup_codes);
    // We only have the hashes at this point (confirmMfa doesn't return them to
    // this test), so mint a fresh known code and hash to exercise the same path.
    const knownCode = "TESTCODE12";
    hashedCodes.push(bcrypt.hashSync(knownCode, 10));
    db.prepare("UPDATE users SET backup_codes = ? WHERE id = ?").run(JSON.stringify(hashedCodes), userId);

    const freshUser = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    assert.equal(mfaController.verifyAndConsumeBackupCode(freshUser, knownCode), true);

    // Second use of the same code must fail — it's single-use.
    const afterUse = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    assert.equal(mfaController.verifyAndConsumeBackupCode(afterUse, knownCode), false);
});

test("disableMfa requires the correct password and clears MFA state on success", () => {
    const wrongPasswordReq = mockReq({ session: { userId }, body: { password: "not-the-password" } });
    const wrongPasswordRes = mockRes();
    mfaController.disableMfa(wrongPasswordReq, wrongPasswordRes);
    assert.equal(wrongPasswordRes.statusCode, 401);

    const req = mockReq({ session: { userId }, body: { password: "correct-horse" } });
    const res = mockRes();
    mfaController.disableMfa(req, res);

    assert.equal(res.body.success, true);
    const user = db.prepare("SELECT totp_enabled, totp_secret, backup_codes FROM users WHERE id = ?").get(userId);
    assert.equal(user.totp_enabled, 0);
    assert.equal(user.totp_secret, null);
    assert.equal(user.backup_codes, null);
});
