const express = require("express");
const router = express.Router();
const ingestController = require("../../controllers/ingestController");
const requireAuth = require("../../middleware/requireAuth");
const requireApiKey = require("../../middleware/requireApiKey");

router.post("/metrics", requireApiKey, ingestController.reportMetrics);
router.get("/metrics/mine", requireAuth, ingestController.getMyMetrics);
router.post("/security-events", requireApiKey, ingestController.reportSecurityEvents);
router.get("/security-events/mine", requireAuth, ingestController.getMySecurityEvents);
router.get("/key", requireAuth, ingestController.getApiKey);
router.post("/key/regenerate", requireAuth, ingestController.regenerateApiKey);

module.exports = router;
