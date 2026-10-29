// Cloudflare Turnstile bot check for the public forms. The page sends the
// widget's token as req.body.turnstileToken; we confirm it with Cloudflare
// before the form handler runs.
//
// Off until TURNSTILE_SECRET_KEY is set in /etc/novateralabs.env, so the
// forms keep working exactly as before while no widget exists.
//
// If Cloudflare's verify API can't be reached, the request is let through
// (and logged) rather than locking everyone — including the owner — out of
// login. The per-IP rate limits in front of this still apply either way.
const clientIp = require("./clientIp");

const VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const TIMEOUT_MS = 5000;

async function requireTurnstile(req, res, next) {
    const secret = process.env.TURNSTILE_SECRET_KEY;
    if (!secret) return next();

    const token = req.body && req.body.turnstileToken;
    if (!token || typeof token !== "string") {
        return res.status(403).json({ error: "Please complete the bot check and try again." });
    }

    let result;
    try {
        const verifyRes = await fetch(VERIFY_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ secret, response: token, remoteip: clientIp(req) }),
            signal: AbortSignal.timeout(TIMEOUT_MS),
        });
        result = await verifyRes.json();
    } catch (err) {
        console.error("[turnstile] Verify API unreachable, allowing request:", err.message);
        return next();
    }

    if (result && result.success) return next();
    res.status(403).json({ error: "Bot check failed. Please try again." });
}

module.exports = requireTurnstile;
module.exports.VERIFY_URL = VERIFY_URL;
