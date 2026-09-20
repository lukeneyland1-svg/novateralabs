const db = require("../db");

module.exports = function requireSubscription(req, res, next) {
    if (req.session && req.session.isOwner) {
        return next();
    }

    const user = db.prepare("SELECT subscription_status FROM users WHERE id = ?").get(req.session.userId);
    if (user && user.subscription_status === "active") {
        return next();
    }

    res.status(402).json({ error: "An active subscription is required." });
};
