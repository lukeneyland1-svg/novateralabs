const express = require("express");
const router = express.Router();
const complianceController = require("../../controllers/complianceController");
const requireAuth = require("../../middleware/requireAuth");
const requireSubscription = require("../../middleware/requireSubscription");

router.get("/export", requireAuth, requireSubscription, complianceController.exportLog);

module.exports = router;
