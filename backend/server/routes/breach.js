const express = require("express");
const router = express.Router();
const breachController = require("../../controllers/breachController");
const rateLimitIp = require("../../middleware/rateLimitIp");
const requireTurnstile = require("../../middleware/requireTurnstile");

router.post("/", rateLimitIp.breachCheck, requireTurnstile, breachController.checkEmailBreach);

module.exports = router;
