const express = require("express");
const router = express.Router();
const ingestController = require("../../controllers/ingestController");
const requireAuth = require("../../middleware/requireAuth");
const requireApiKey = require("../../middleware/requireApiKey");
const requireSubscription = require("../../middleware/requireSubscription");

// The agent's own reporting endpoints stay open regardless of subscription
// status — an agent already running for a lapsed account keeps reporting in
// rather than erroring in a cron job. Only the dashboard-facing read/manage
// endpoints below require an active subscription.
router.post("/metrics", requireApiKey, ingestController.reportMetrics);
router.get("/metrics/mine", requireAuth, requireSubscription, ingestController.getMyMetrics);
router.post("/security-events", requireApiKey, ingestController.reportSecurityEvents);
router.get("/security-events/mine", requireAuth, requireSubscription, ingestController.getMySecurityEvents);
router.get("/key", requireAuth, requireSubscription, ingestController.getApiKey);
router.post("/key/regenerate", requireAuth, requireSubscription, ingestController.regenerateApiKey);

module.exports = router;
