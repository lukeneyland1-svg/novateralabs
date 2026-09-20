const db = require("../db");

// secrets.js is gitignored and won't exist in CI or a fresh checkout —
// fall back to environment variables so this module can still load there.
let secrets = {};
try {
    secrets = require("../secrets");
} catch {}

const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY || secrets.ABUSEIPDB_API_KEY;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
// A failed lookup (bad/missing key, quota exceeded, network error) is cached
// too, just for much less time — otherwise a persistently failing key would
// get retried on every 10-second refresh cycle forever instead of backing off.
const FAILURE_CACHE_TTL_MS = 60 * 60 * 1000;
const ABUSE_SCORE_THRESHOLD = 50;

function isPrivateIP(ip) {
    if (!ip) return true;
    return /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(ip);
}
exports.isPrivateIP = isPrivateIP;

function cachedRowToResult(row) {
    return { abuseScore: row.abuse_score, countryCode: row.country_code, isMalicious: !!row.is_malicious };
}

async function fetchFromAbuseIPDB(ip) {
    const res = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
        { headers: { Key: ABUSEIPDB_API_KEY, Accept: "application/json" } }
    );
    if (!res.ok) {
        throw new Error(`AbuseIPDB responded ${res.status}`);
    }
    const body = await res.json();
    return {
        abuseScore: body.data.abuseConfidenceScore,
        countryCode: body.data.countryCode || null,
        isMalicious: body.data.abuseConfidenceScore >= ABUSE_SCORE_THRESHOLD,
    };
}

exports.lookupIP = async (ip) => {
    if (isPrivateIP(ip) || !ABUSEIPDB_API_KEY) {
        return null;
    }

    const cached = db.prepare("SELECT * FROM ip_reputation WHERE ip = ?").get(ip);
    if (cached) {
        const age = Date.now() - new Date(cached.checked_at).getTime();
        const isFailureMarker = cached.abuse_score === null;
        if (age < (isFailureMarker ? FAILURE_CACHE_TTL_MS : CACHE_TTL_MS)) {
            return isFailureMarker ? null : cachedRowToResult(cached);
        }
    }

    const upsert = (abuseScore, countryCode, isMalicious) => {
        db.prepare(`
            INSERT INTO ip_reputation (ip, abuse_score, country_code, is_malicious, checked_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                abuse_score = excluded.abuse_score,
                country_code = excluded.country_code,
                is_malicious = excluded.is_malicious,
                checked_at = excluded.checked_at
        `).run(ip, abuseScore, countryCode, isMalicious, new Date().toISOString());
    };

    try {
        const result = await fetchFromAbuseIPDB(ip);
        upsert(result.abuseScore, result.countryCode, result.isMalicious ? 1 : 0);
        return result;
    } catch (err) {
        console.error(`[threatIntel] Lookup failed for ${ip}:`, err.message);
        // Cache the failure itself (briefly) so a bad/missing key or an outage
        // backs off instead of retrying every single refresh cycle.
        upsert(null, null, null);
        return null;
    }
};

exports.enrichAlerts = async (alerts) => {
    const uniqueIPs = [...new Set(alerts.map(a => a.ip).filter(Boolean))];
    const entries = await Promise.all(uniqueIPs.map(async (ip) => [ip, await exports.lookupIP(ip)]));
    const byIP = new Map(entries);

    return alerts.map(a => ({ ...a, reputation: a.ip ? (byIP.get(a.ip) || null) : null }));
};
