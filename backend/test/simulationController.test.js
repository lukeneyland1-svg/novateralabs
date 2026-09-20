const test = require("node:test");
const assert = require("node:assert/strict");

const simulationController = require("../controllers/simulationController");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

test("simulateAttack returns a detected brute-force pattern with consistent bucket counts", () => {
    const req = mockReq();
    const res = mockRes();

    simulationController.simulateAttack(req, res);

    assert.equal(res.statusCode, 200);
    const body = res.body;
    assert.equal(body.simulatedIp, "203.0.113.55");
    assert.equal(body.attemptCount, 40);
    assert.equal(body.flaggedCount, 40);
    assert.equal(body.detected, true);
    assert.equal(body.buckets.length, 10);
    assert.equal(body.buckets.reduce((a, b) => a + b, 0), body.attemptCount);
    assert.equal(body.sampleEvents.length, 3);
});
