const express = require("express");
const router = express.Router();
const breachController = require("../../controllers/breachController");
const rateLimitIp = require("../../middleware/rateLimitIp");

router.post("/", rateLimitIp.breachCheck, breachController.checkEmailBreach);

module.exports = router;
