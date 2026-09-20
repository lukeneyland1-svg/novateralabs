const db = require("../db");
const { stripe, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_ID } = require("../services/stripeClient");

exports.createCheckoutSession = async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.create({
            mode: "subscription",
            line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
            client_reference_id: String(req.session.userId),
            success_url: "https://novateralabs.com/dashboard.html?billing=success",
            cancel_url: "https://novateralabs.com/dashboard.html?billing=cancelled",
        });

        res.json({ url: session.url });
    } catch (err) {
        console.error("Checkout session error:", err);
        res.status(500).json({ error: "Could not start checkout." });
    }
};

exports.handleWebhook = (req, res) => {
    let event;
    try {
        const signature = req.headers["stripe-signature"];
        event = stripe.webhooks.constructEvent(req.body, signature, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error("Webhook signature verification failed:", err.message);
        return res.status(400).json({ error: "Invalid signature" });
    }

    try {
        if (event.type === "checkout.session.completed") {
            const session = event.data.object;
            db.prepare(`
                UPDATE users SET subscription_status = 'active', stripe_customer_id = ?, stripe_subscription_id = ?
                WHERE id = ?
            `).run(session.customer, session.subscription, Number(session.client_reference_id));
        } else if (event.type === "customer.subscription.deleted") {
            const subscription = event.data.object;
            db.prepare("UPDATE users SET subscription_status = 'canceled' WHERE stripe_subscription_id = ?")
                .run(subscription.id);
        }

        res.json({ received: true });
    } catch (err) {
        console.error("Webhook handling error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};
