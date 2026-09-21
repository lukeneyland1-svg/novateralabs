process.env.NOVATERALABS_DB_PATH = ":memory:";

const test = require("node:test");
const assert = require("node:assert/strict");

const statusController = require("../controllers/statusController");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

test("getStatus returns a status summary with no session required", () => {
    const req = mockReq({ session: null });
    const res = mockRes();

    statusController.getStatus(req, res);

    assert.equal(res.statusCode, 200);
    assert.ok("overall" in res.body);
    assert.ok(Array.isArray(res.body.components));
});
