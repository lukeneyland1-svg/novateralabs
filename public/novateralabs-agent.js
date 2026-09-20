#!/usr/bin/env node
/*
 * NovaTeraLabs metrics agent — reports this machine's CPU/RAM/uptime to your
 * dashboard. Zero dependencies; only needs Node.js.
 *
 * Setup:
 *   1. Get your API key from the "Connect Your Server" panel on your dashboard.
 *   2. Run it once by hand to check it works:
 *        NOVATERALABS_API_KEY=your-key-here node novateralabs-agent.js
 *   3. Add it to cron to report on a schedule (every minute):
 *        * * * * * NOVATERALABS_API_KEY=your-key-here node /path/to/novateralabs-agent.js
 */
const os = require("os");
const https = require("https");

const API_KEY = process.env.NOVATERALABS_API_KEY;
const ENDPOINT = "https://novateralabs.com/api/ingest/metrics";

if (!API_KEY) {
    console.error("Missing NOVATERALABS_API_KEY environment variable.");
    process.exit(1);
}

const cpuLoad = Math.min(100, (os.loadavg()[0] / os.cpus().length) * 100);
const ramUsage = (1 - os.freemem() / os.totalmem()) * 100;
const uptimeMinutes = os.uptime() / 60;

const payload = JSON.stringify({
    cpu_load: cpuLoad,
    ram_usage: ramUsage,
    uptime_minutes: uptimeMinutes,
});

const url = new URL(ENDPOINT);
const req = https.request(
    {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(payload),
            "X-API-Key": API_KEY,
        },
    },
    (res) => {
        let body = "";
        res.on("data", (chunk) => { body += chunk; });
        res.on("end", () => {
            if (res.statusCode >= 200 && res.statusCode < 300) {
                console.log("Reported successfully.");
            } else {
                console.error(`Report failed (${res.statusCode}): ${body}`);
                process.exit(1);
            }
        });
    }
);

req.on("error", (err) => {
    console.error("Report failed:", err.message);
    process.exit(1);
});

req.write(payload);
req.end();
