const express = require("express");
const router = express.Router();
const securityController = require("../../controllers/securityController");

router.get("/", securityController.getSecurityEvents);

module.exports = router;
