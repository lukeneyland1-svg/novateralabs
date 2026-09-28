// Per-account webhook URLs, stored on users.webhook_url and set via the
// dashboard -- no longer a single operator-level secret. Every caller is
// responsible for looking up whichever account's URL applies and passing it
// in explicitly.
exports.sendToWebhook = async (text, webhookUrl) => {
    if (!webhookUrl) {
        return true; // Not configured — a no-op, not an error, same treatment as threatIntel without an API key.
    }

    try {
        const res = await fetch(webhookUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text }),
        });
        if (!res.ok) {
            console.error(`[webhookNotifier] Webhook responded ${res.status}`);
            return false;
        }
        return true;
    } catch (err) {
        console.error("[webhookNotifier] Failed to send webhook:", err.message);
        return false;
    }
};
