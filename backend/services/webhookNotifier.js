// secrets.js is gitignored and won't exist in CI or a fresh checkout —
// fall back to environment variables so this module can still load there.
let secrets = {};
try {
    secrets = require("../secrets");
} catch {}

const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || secrets.SLACK_WEBHOOK_URL;

exports.sendToWebhook = async (text) => {
    if (!SLACK_WEBHOOK_URL) {
        return; // Not configured — a no-op, not an error, same treatment as threatIntel without an API key.
    }

    try {
        const res = await fetch(SLACK_WEBHOOK_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text }),
        });
        if (!res.ok) {
            console.error(`[webhookNotifier] Webhook responded ${res.status}`);
        }
    } catch (err) {
        console.error("[webhookNotifier] Failed to send webhook:", err.message);
    }
};
