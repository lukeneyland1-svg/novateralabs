process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.test/fake-webhook";

const test = require("node:test");
const assert = require("node:assert/strict");

const webhookNotifier = require("../services/webhookNotifier");

const originalFetch = global.fetch;
test.after(() => { global.fetch = originalFetch; });

test("sendToWebhook posts the correct JSON body to the configured URL", async () => {
    let capturedUrl = null;
    let capturedOptions = null;
    global.fetch = async (url, options) => {
        capturedUrl = url;
        capturedOptions = options;
        return { ok: true, status: 200 };
    };

    await webhookNotifier.sendToWebhook("test message");

    assert.equal(capturedUrl, "https://hooks.slack.test/fake-webhook");
    assert.equal(capturedOptions.method, "POST");
    assert.equal(capturedOptions.headers["Content-Type"], "application/json");
    assert.deepEqual(JSON.parse(capturedOptions.body), { text: "test message" });
});

test("sendToWebhook does not throw when the webhook call fails", async () => {
    global.fetch = async () => { throw new Error("network down"); };

    await assert.doesNotReject(() => webhookNotifier.sendToWebhook("test message"));
});

test("sendToWebhook does not throw when the webhook responds with an error status", async () => {
    global.fetch = async () => ({ ok: false, status: 500 });

    await assert.doesNotReject(() => webhookNotifier.sendToWebhook("test message"));
});
