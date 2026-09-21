const express = require("express");
const router = express.Router();
const scanController = require("../../controllers/scanController");
const requireAuth = require("../../middleware/requireAuth");
const requireSubscription = require("../../middleware/requireSubscription");

router.post("/", requireAuth, requireSubscription, scanController.runScan);
router.get("/target", requireAuth, requireSubscription, scanController.getScanTarget);

module.exports = router;
