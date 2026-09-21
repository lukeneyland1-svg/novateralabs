const express = require("express");
const router = express.Router();
const apiController = require("../../controllers/apiController");
const requireApiKey = require("../../middleware/requireApiKey");
const requireSubscription = require("../../middleware/requireSubscription");

router.get("/metrics", requireApiKey, requireSubscription, apiController.getMetrics);
router.get("/security-events", requireApiKey, requireSubscription, apiController.getSecurityEvents);
router.get("/compliance-log", requireApiKey, requireSubscription, apiController.getComplianceLog);

module.exports = router;
