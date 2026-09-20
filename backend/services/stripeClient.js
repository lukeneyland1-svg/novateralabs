const Stripe = require("stripe");

// secrets.js is gitignored and won't exist in CI or a fresh checkout —
// fall back to environment variables so this module can still load there.
let secrets = {};
try {
    secrets = require("../secrets");
} catch {}

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || secrets.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || secrets.STRIPE_WEBHOOK_SECRET;
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID || secrets.STRIPE_PRICE_ID;

// The Stripe constructor throws if given no key at all (unlike nodemailer's
// lazier createTransport) — a placeholder keeps this module loadable in
// CI/tests, where real Stripe calls are mocked rather than actually made.
const stripe = Stripe(STRIPE_SECRET_KEY || "sk_test_placeholder");

module.exports = { stripe, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_ID };
