// Per-visitor rate limits for the public forms (login, MFA, password reset,
// contact, breach check), counted by the visitor's real IP (see clientIp.js).
// Same approach as rateLimitApiKey: fixed windows kept in memory, so a
// restart resets everyone's counter — fine for a limit whose job is to stop
// password guessing and spam floods, not to meter real visitors.
const clientIp = require("./clientIp");

const limiters = [];

function createIpRateLimit({ limit, windowMs, message }) {
    const windows = new Map(); // ip -> { start, count }

    function rateLimitIp(req, res, next) {
        const now = Date.now();
        const ip = clientIp(req);
        let entry = windows.get(ip);
        if (!entry || now - entry.start >= windowMs) {
            entry = { start: now, count: 0 };
            windows.set(ip, entry);
        }
        entry.count++;

        if (entry.count > limit) {
            const resetSeconds = Math.ceil((entry.start + windowMs - now) / 1000);
            const minutes = Math.ceil(resetSeconds / 60);
            res.setHeader("Retry-After", String(resetSeconds));
            return res.status(429).json({ error: `${message} Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.` });
        }
        next();
    }

    // Sweep expired windows so the map can't grow forever. unref() so this
    // never keeps tests/scripts alive.
    setInterval(() => {
        const now = Date.now();
        for (const [ip, entry] of windows) {
            if (now - entry.start >= windowMs) windows.delete(ip);
        }
    }, Math.min(windowMs, 10 * 60 * 1000)).unref();

    rateLimitIp._reset = () => windows.clear();
    limiters.push(rateLimitIp);
    return rateLimitIp;
}

const MINUTE = 60 * 1000;

module.exports = {
    createIpRateLimit,
    login: createIpRateLimit({ limit: 5, windowMs: 30 * MINUTE, message: "Too many login attempts." }),
    mfa: createIpRateLimit({ limit: 5, windowMs: 30 * MINUTE, message: "Too many verification attempts." }),
    forgotPassword: createIpRateLimit({ limit: 3, windowMs: 60 * MINUTE, message: "Too many password reset requests." }),
    resetPassword: createIpRateLimit({ limit: 10, windowMs: 60 * MINUTE, message: "Too many password reset attempts." }),
    contact: createIpRateLimit({ limit: 5, windowMs: 60 * MINUTE, message: "Too many messages sent." }),
    breachCheck: createIpRateLimit({ limit: 10, windowMs: 60 * MINUTE, message: "Too many breach checks." }),
    _resetAll: () => limiters.forEach(l => l._reset()),
};
