process.env.NOVATERALABS_DB_PATH = ":memory:";
process.env.STRIPE_WEBHOOK_SECRET = "whsec_test_secret";
process.env.STRIPE_PRICE_ID = "price_test_123";

const test = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");

const db = require("../db");
const billingController = require("../controllers/billingController");
const { stripe } = require("../services/stripeClient");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const userId = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run("customer", bcrypt.hashSync("password123", 10)).lastInsertRowid;

const originalCreate = stripe.checkout.sessions.create;
test.after(() => { stripe.checkout.sessions.create = originalCreate; });

test("createCheckoutSession creates a subscription checkout with the right price and client_reference_id", async () => {
    let capturedParams = null;
    stripe.checkout.sessions.create = async (params) => {
        capturedParams = params;
        return { url: "https://checkout.stripe.com/fake-session" };
    };

    const req = mockReq({ session: { userId } });
    const res = mockRes();
    await billingController.createCheckoutSession(req, res);

    assert.deepEqual(res.body, { url: "https://checkout.stripe.com/fake-session" });
    assert.equal(capturedParams.mode, "subscription");
    assert.equal(capturedParams.client_reference_id, String(userId));
    assert.equal(capturedParams.line_items[0].price, "price_test_123");
});

test("createCheckoutSession returns 500 when Stripe errors", async () => {
    stripe.checkout.sessions.create = async () => { throw new Error("stripe is down"); };

    const req = mockReq({ session: { userId } });
    const res = mockRes();
    await billingController.createCheckoutSession(req, res);

    assert.equal(res.statusCode, 500);
});

// Signs a fake event locally with Stripe's own test helper — no real Stripe
// account or network call involved, just the same HMAC scheme constructEvent
// verifies against.
function signPayload(payloadObj) {
    const payload = JSON.stringify(payloadObj);
    const header = stripe.webhooks.generateTestHeaderString({ payload, secret: "whsec_test_secret" });
    return { body: Buffer.from(payload, "utf8"), header };
}

test("handleWebhook rejects a badly-signed payload", () => {
    const req = mockReq({ headers: { "stripe-signature": "bad-signature" } });
    req.body = Buffer.from(JSON.stringify({ type: "checkout.session.completed" }));
    const res = mockRes();

    billingController.handleWebhook(req, res);

    assert.equal(res.statusCode, 400);
});

test("handleWebhook activates the right account on checkout.session.completed", () => {
    const { body, header } = signPayload({
        id: "evt_1",
        type: "checkout.session.completed",
        data: { object: { client_reference_id: String(userId), customer: "cus_123", subscription: "sub_456" } },
    });
    const req = mockReq({ headers: { "stripe-signature": header } });
    req.body = body;
    const res = mockRes();

    billingController.handleWebhook(req, res);

    assert.deepEqual(res.body, { received: true });
    const user = db.prepare("SELECT subscription_status, stripe_customer_id, stripe_subscription_id FROM users WHERE id = ?").get(userId);
    assert.equal(user.subscription_status, "active");
    assert.equal(user.stripe_customer_id, "cus_123");
    assert.equal(user.stripe_subscription_id, "sub_456");
});

test("handleWebhook reverts subscription_status on customer.subscription.deleted", () => {
    const { body, header } = signPayload({
        id: "evt_2",
        type: "customer.subscription.deleted",
        data: { object: { id: "sub_456" } },
    });
    const req = mockReq({ headers: { "stripe-signature": header } });
    req.body = body;
    const res = mockRes();

    billingController.handleWebhook(req, res);

    const user = db.prepare("SELECT subscription_status FROM users WHERE id = ?").get(userId);
    assert.equal(user.subscription_status, "canceled");
});
