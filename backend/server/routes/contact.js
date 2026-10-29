const express = require("express");
const router = express.Router();
const contactController = require("../../controllers/contactController");
const rateLimitIp = require("../../middleware/rateLimitIp");
const requireTurnstile = require("../../middleware/requireTurnstile");

router.post("/", rateLimitIp.contact, requireTurnstile, contactController.sendContactMessage);

module.exports = router;
