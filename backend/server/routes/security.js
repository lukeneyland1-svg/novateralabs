const express = require("express");
const router = express.Router();
const securityController = require("../../controllers/securityController");

router.get("/", securityController.getSecurityEvents);
router.get("/stream", securityController.streamSecurityEvents);

module.exports = router;
