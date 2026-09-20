const express = require("express");
const router = express.Router();
const billingController = require("../../controllers/billingController");
const requireAuth = require("../../middleware/requireAuth");

router.post("/checkout", requireAuth, billingController.createCheckoutSession);
router.post("/webhook", express.raw({ type: "application/json" }), billingController.handleWebhook);

module.exports = router;
