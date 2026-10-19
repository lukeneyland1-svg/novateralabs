const express = require("express");
const router = express.Router();
const apiController = require("../../controllers/apiController");
const requireApiKey = require("../../middleware/requireApiKey");
const requireSubscription = require("../../middleware/requireSubscription");
const rateLimitApiKey = require("../../middleware/rateLimitApiKey");

router.get("/metrics", requireApiKey, rateLimitApiKey, requireSubscription, apiController.getMetrics);
router.get("/security-events", requireApiKey, rateLimitApiKey, requireSubscription, apiController.getSecurityEvents);
router.get("/compliance-log", requireApiKey, rateLimitApiKey, requireSubscription, apiController.getComplianceLog);

module.exports = router;
