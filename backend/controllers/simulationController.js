const { Worker } = require("worker_threads");
const os = require("os");
const path = require("path");

/* ---------------- CPU load spike (real, bounded, loads ALL cores) ---------------- */
exports.simulateCpuSpike = (req, res) => {
    const durationSeconds = 10;
    const workerCount = Math.min(os.cpus().length, 4);
    const beforeLoad = os.loadavg()[0];

    let completed = 0;
    let hadError = false;

    for (let i = 0; i < workerCount; i++) {
        const worker = new Worker(path.join(__dirname, "..", "workers", "cpuSpikeWorker.js"), {
            workerData: { durationSeconds },
        });

        worker.on("error", (err) => {
            console.error("CPU spike worker error:", err);
            hadError = true;
        });

        worker.on("exit", () => {
            completed++;
            if (completed === workerCount && !res.headersSent) {
                if (hadError) {
                    return res.status(500).json({ error: "Simulation failed to run." });
                }
                const afterLoad = os.loadavg()[0];
                res.json({ durationSeconds, workerCount, beforeLoad, afterLoad });
            }
        });
    }
};

/* ---------------- Simulated brute-force attack (safe: synthetic data only) ---------------- */
const SEVERITY_RULES = {
    critical: ["failed password", "invalid user", "authentication failure"],
    high: ["connection closed by", "disconnect"],
    medium: ["accepted password", "session opened"],
};

function classify(message) {
    const lower = message.toLowerCase();
    for (const [severity, keywords] of Object.entries(SEVERITY_RULES)) {
        if (keywords.some((k) => lower.includes(k))) return severity;
    }
    return "low";
}

exports.simulateAttack = (req, res) => {
    // 203.0.113.0/24 is a reserved "documentation" IP range (RFC 5737) —
    // guaranteed to never be a real, routable address. Safe to use here.
    const attackerIp = "203.0.113.55";
    const attemptCount = 40;
    const windowSeconds = 90;
    const BUCKET_COUNT = 10;

    const events = [];
    const now = Date.now();
    for (let i = 0; i < attemptCount; i++) {
        const message = `Failed password for root from ${attackerIp} port ${40000 + i} ssh2`;
        events.push({
            timestamp: new Date(now - (attemptCount - i) * ((windowSeconds * 1000) / attemptCount)).toISOString(),
            message,
            ip: attackerIp,
            severity: classify(message),
        });
    }

    const flaggedCount = events.filter((e) => e.severity === "critical" || e.severity === "high").length;
    const detected = flaggedCount >= 5; // matches the real brute-force threshold used elsewhere on the site

    // Bucket events into time slices for the timeline chart.
    const buckets = new Array(BUCKET_COUNT).fill(0);
    events.forEach((_, i) => {
        const bucketIndex = Math.min(BUCKET_COUNT - 1, Math.floor((i / attemptCount) * BUCKET_COUNT));
        buckets[bucketIndex]++;
    });

    res.json({
        simulatedIp: attackerIp,
        attemptCount,
        windowSeconds,
        flaggedCount,
        detected,
        buckets,
        sampleEvents: events.slice(0, 3),
    });
};
