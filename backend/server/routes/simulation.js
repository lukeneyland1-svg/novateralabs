const express = require("express");
const router = express.Router();
const simulationController = require("../../controllers/simulationController");

router.post("/cpu-spike", simulationController.simulateCpuSpike);
router.post("/attack", simulationController.simulateAttack);

module.exports = router;
