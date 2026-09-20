const db = require("../db");

// Machine-to-machine auth for the agent/ingestion endpoints — there's no
// browser session here, so the matched account goes on req.apiUserId rather
// than req.session (which doesn't exist for these requests).
module.exports = function requireApiKey(req, res, next) {
    const apiKey = req.headers["x-api-key"];
    if (!apiKey) {
        return res.status(401).json({ error: "Missing API key" });
    }

    const user = db.prepare("SELECT id FROM users WHERE api_key = ?").get(apiKey);
    if (!user) {
        return res.status(401).json({ error: "Invalid API key" });
    }

    req.apiUserId = user.id;
    next();
};
