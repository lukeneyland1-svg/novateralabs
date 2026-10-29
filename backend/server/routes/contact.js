const express = require("express");
const router = express.Router();
const contactController = require("../../controllers/contactController");
const rateLimitIp = require("../../middleware/rateLimitIp");

router.post("/", rateLimitIp.contact, contactController.sendContactMessage);

module.exports = router;
