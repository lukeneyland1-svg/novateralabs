const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const db = require("../db");
const { transporter, EMAIL_USER } = require("../services/mailer");
const { verifyAndConsumeBackupCode, safeVerifyTotp } = require("./mfaController");

const RESET_TOKEN_TTL_MS = 30 * 60 * 1000;

exports.login = (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: "username and password are required" });
        }

        const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
        if (!user) {
            return res.status(401).json({ error: "Invalid username or password" });
        }

        const match = bcrypt.compareSync(password, user.password_hash);
        if (!match) {
            return res.status(401).json({ error: "Invalid username or password" });
        }

        if (user.totp_enabled) {
            req.session.pendingMfaUserId = user.id;
            return res.json({ mfaRequired: true });
        }

        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.isOwner = !!user.is_owner;
        res.json({ success: true, username: user.username });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

exports.verifyMfaLogin = async (req, res) => {
    try {
        const { code } = req.body;
        if (!req.session.pendingMfaUserId || !code) {
            return res.status(400).json({ error: "No pending login to verify." });
        }

        const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.pendingMfaUserId);
        if (!user || !user.totp_enabled) {
            return res.status(400).json({ error: "No pending login to verify." });
        }

        const result = await safeVerifyTotp(user.totp_secret, code);
        const validCode = result.valid || verifyAndConsumeBackupCode(user, code);
        if (!validCode) {
            return res.status(401).json({ error: "Invalid code." });
        }

        delete req.session.pendingMfaUserId;
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.isOwner = !!user.is_owner;
        res.json({ success: true, username: user.username });
    } catch (err) {
        console.error("MFA login verify error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

exports.logout = (req, res) => {
    req.session.destroy(() => {
        res.clearCookie("connect.sid");
        res.json({ success: true });
    });
};

exports.checkSession = (req, res) => {
    if (req.session && req.session.userId) {
        const user = db.prepare("SELECT totp_enabled FROM users WHERE id = ?").get(req.session.userId);
        res.json({
            authenticated: true,
            username: req.session.username,
            mfaEnabled: !!(user && user.totp_enabled),
            isOwner: !!req.session.isOwner,
        });
    } else {
        res.status(401).json({ authenticated: false });
    }
};

// Always responds the same way whether or not the email matches an account,
// so this endpoint can't be used to discover which emails have accounts.
const GENERIC_RESET_RESPONSE = { success: true, message: "If that email matches an account, a reset link has been sent." };

exports.requestPasswordReset = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ error: "email is required" });
        }

        const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
        if (!user) {
            return res.json(GENERIC_RESET_RESPONSE);
        }

        const token = crypto.randomBytes(32).toString("hex");
        const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS).toISOString();
        db.prepare("INSERT INTO password_resets (token, user_id, expires_at) VALUES (?, ?, ?)")
            .run(token, user.id, expiresAt);

        const resetUrl = `https://novateralabs.com/reset-password.html?token=${token}`;
        await transporter.sendMail({
            from: `"NovaTeraLabs Security" <${EMAIL_USER}>`,
            to: email,
            subject: "Reset your NovaTeraLabs password",
            text: `A password reset was requested for your account.\n\nReset your password: ${resetUrl}\n\nThis link expires in 30 minutes. If you didn't request this, you can ignore this email.`,
        });

        res.json(GENERIC_RESET_RESPONSE);
    } catch (err) {
        console.error("Password reset request error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

exports.resetPassword = (req, res) => {
    try {
        const { token, password } = req.body;
        if (!token || !password) {
            return res.status(400).json({ error: "token and password are required" });
        }
        if (password.length < 8) {
            return res.status(400).json({ error: "Password must be at least 8 characters." });
        }

        const reset = db.prepare("SELECT * FROM password_resets WHERE token = ?").get(token);
        if (!reset || reset.used || new Date(reset.expires_at).getTime() < Date.now()) {
            return res.status(400).json({ error: "This reset link is invalid or has expired." });
        }

        const hash = bcrypt.hashSync(password, 10);
        db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, reset.user_id);
        db.prepare("UPDATE password_resets SET used = 1 WHERE user_id = ?").run(reset.user_id);

        res.json({ success: true });
    } catch (err) {
        console.error("Password reset error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};
