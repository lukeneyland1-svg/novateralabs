const db = require("../db");

module.exports = function requireSubscription(req, res, next) {
    // Works for either auth path: a browser session (req.session) or an
    // API-key request (req.apiUserId/req.apiIsOwner, set by requireApiKey).
    // For a session-based request the API-key fields are simply undefined,
    // so this is a no-op fallback — behavior for existing callers is unchanged.
    const isOwner = (req.session && req.session.isOwner) || req.apiIsOwner;
    if (isOwner) {
        return next();
    }

    const userId = (req.session && req.session.userId) || req.apiUserId;
    const user = db.prepare("SELECT subscription_status FROM users WHERE id = ?").get(userId);
    if (user && user.subscription_status === "active") {
        return next();
    }

    res.status(402).json({ error: "An active subscription is required." });
};
