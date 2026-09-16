const express = require("express");
const router = express.Router();
const automationController = require("../../controllers/automationController");

router.get("/", automationController.getAutomationTasks);
router.post("/", automationController.createAutomationTask);

module.exports = router;
