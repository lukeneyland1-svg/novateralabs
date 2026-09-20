const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { generateSecret, generate, verify, generateURI } = require("otplib");
const QRCode = require("qrcode");
const db = require("../db");

const BACKUP_CODE_COUNT = 10;

function generateBackupCodes() {
    // 10-character alphanumeric codes, e.g. "A1B2C3D4E5" — easy to read back
    // from a printed page if needed.
    return Array.from({ length: BACKUP_CODE_COUNT }, () =>
        crypto.randomBytes(6).toString("hex").slice(0, 10).toUpperCase()
    );
}

// otplib's verify() throws instead of returning { valid: false } when the
// token isn't a 6-digit TOTP code (e.g. a 10-character backup code gets
// submitted here) — treat that as simply "not a valid code" either way.
async function safeVerifyTotp(secret, token) {
    try {
        return await verify({ secret, token });
    } catch {
        return { valid: false };
    }
}
exports.safeVerifyTotp = safeVerifyTotp;

exports.setupMfa = async (req, res) => {
    try {
        const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId);
        const secret = generateSecret();
        db.prepare("UPDATE users SET totp_secret = ? WHERE id = ?").run(secret, user.id);

        const otpauthUrl = generateURI({ issuer: "NovaTeraLabs", label: user.username, secret });
        const qrCode = await QRCode.toDataURL(otpauthUrl);

        res.json({ secret, qrCode });
    } catch (err) {
        console.error("MFA setup error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

exports.confirmMfa = async (req, res) => {
    try {
        const { code } = req.body;
        if (!code) {
            return res.status(400).json({ error: "code is required" });
        }

        const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId);
        if (!user.totp_secret) {
            return res.status(400).json({ error: "Run MFA setup before confirming." });
        }

        const result = await safeVerifyTotp(user.totp_secret, code);
        if (!result.valid) {
            return res.status(400).json({ error: "Invalid code." });
        }

        const backupCodes = generateBackupCodes();
        const hashedCodes = backupCodes.map(c => bcrypt.hashSync(c, 10));
        db.prepare("UPDATE users SET totp_enabled = 1, backup_codes = ? WHERE id = ?")
            .run(JSON.stringify(hashedCodes), user.id);

        res.json({ success: true, backupCodes });
    } catch (err) {
        console.error("MFA confirm error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

// Shared with authController's login-MFA step: checks a submitted code
// against the user's remaining backup codes and, on a match, removes that
// one code so it can't be used again.
exports.verifyAndConsumeBackupCode = (user, code) => {
    if (!user.backup_codes) return false;
    const hashedCodes = JSON.parse(user.backup_codes);
    const matchIndex = hashedCodes.findIndex(hash => bcrypt.compareSync(code, hash));
    if (matchIndex === -1) return false;

    hashedCodes.splice(matchIndex, 1);
    db.prepare("UPDATE users SET backup_codes = ? WHERE id = ?").run(JSON.stringify(hashedCodes), user.id);
    return true;
};

exports.disableMfa = (req, res) => {
    try {
        const { password } = req.body;
        if (!password) {
            return res.status(400).json({ error: "password is required" });
        }

        const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId);
        if (!bcrypt.compareSync(password, user.password_hash)) {
            return res.status(401).json({ error: "Incorrect password." });
        }

        db.prepare("UPDATE users SET totp_enabled = 0, totp_secret = NULL, backup_codes = NULL WHERE id = ?")
            .run(user.id);

        res.json({ success: true });
    } catch (err) {
        console.error("MFA disable error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};
