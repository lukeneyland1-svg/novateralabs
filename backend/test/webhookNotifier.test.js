const test = require("node:test");
const assert = require("node:assert/strict");

const webhookNotifier = require("../services/webhookNotifier");

const originalFetch = global.fetch;
test.after(() => { global.fetch = originalFetch; });

test("sendToWebhook posts the correct JSON body to the given URL", async () => {
    let capturedUrl = null;
    let capturedOptions = null;
    global.fetch = async (url, options) => {
        capturedUrl = url;
        capturedOptions = options;
        return { ok: true, status: 200 };
    };

    const result = await webhookNotifier.sendToWebhook("test message", "https://hooks.slack.test/fake-webhook");

    assert.equal(result, true);
    assert.equal(capturedUrl, "https://hooks.slack.test/fake-webhook");
    assert.equal(capturedOptions.method, "POST");
    assert.equal(capturedOptions.headers["Content-Type"], "application/json");
    assert.deepEqual(JSON.parse(capturedOptions.body), { text: "test message" });
});

test("sendToWebhook is a no-op and returns true when no URL is given", async () => {
    let called = false;
    global.fetch = async () => { called = true; return { ok: true, status: 200 }; };

    const result = await webhookNotifier.sendToWebhook("test message", null);

    assert.equal(called, false);
    assert.equal(result, true);
});

test("sendToWebhook does not throw and returns false when the webhook call fails", async () => {
    global.fetch = async () => { throw new Error("network down"); };

    const result = await webhookNotifier.sendToWebhook("test message", "https://hooks.slack.test/fake-webhook");

    assert.equal(result, false);
});

test("sendToWebhook does not throw and returns false when the webhook responds with an error status", async () => {
    global.fetch = async () => ({ ok: false, status: 500 });

    const result = await webhookNotifier.sendToWebhook("test message", "https://hooks.slack.test/fake-webhook");

    assert.equal(result, false);
});
