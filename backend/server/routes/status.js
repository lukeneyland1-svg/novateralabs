const express = require("express");
const router = express.Router();
const statusController = require("../../controllers/statusController");

// Public — a status page must work even when a customer can't log in.
router.get("/", statusController.getStatus);

module.exports = router;
