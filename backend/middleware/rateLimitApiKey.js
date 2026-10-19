// Per-account rate limit for the public read-only API (/api/v1). Runs after
// requireApiKey, so it counts by req.apiUserId — one budget per account, no
// matter how many IPs or scripts share the key. Fixed one-minute windows,
// kept in memory: a restart just resets everyone's counter, which is fine
// for a limit whose only job is to stop runaway scripts from hammering the
// server.
const LIMIT = 60;
const WINDOW_MS = 60 * 1000;

const windows = new Map(); // userId -> { start, count }

function rateLimitApiKey(req, res, next) {
    const now = Date.now();
    let entry = windows.get(req.apiUserId);
    if (!entry || now - entry.start >= WINDOW_MS) {
        entry = { start: now, count: 0 };
        windows.set(req.apiUserId, entry);
    }
    entry.count++;

    const resetSeconds = Math.ceil((entry.start + WINDOW_MS - now) / 1000);
    res.setHeader("RateLimit-Limit", String(LIMIT));
    res.setHeader("RateLimit-Remaining", String(Math.max(0, LIMIT - entry.count)));
    res.setHeader("RateLimit-Reset", String(resetSeconds));

    if (entry.count > LIMIT) {
        res.setHeader("Retry-After", String(resetSeconds));
        return res.status(429).json({ error: `Rate limit exceeded — max ${LIMIT} requests per minute. Try again in ${resetSeconds}s.` });
    }
    next();
}

// Old windows are dead weight once they expire; sweep them occasionally so
// the map can't grow forever. unref() so this never keeps tests/scripts alive.
setInterval(() => {
    const now = Date.now();
    for (const [userId, entry] of windows) {
        if (now - entry.start >= WINDOW_MS) windows.delete(userId);
    }
}, WINDOW_MS).unref();

module.exports = rateLimitApiKey;
module.exports.LIMIT = LIMIT;
module.exports._reset = () => windows.clear();
