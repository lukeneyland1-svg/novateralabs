const express = require("express");
const router = express.Router();
const breachController = require("../../controllers/breachController");

router.post("/", breachController.checkEmailBreach);

module.exports = router;
