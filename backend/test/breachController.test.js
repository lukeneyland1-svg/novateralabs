const test = require("node:test");
const assert = require("node:assert/strict");

const breachController = require("../controllers/breachController");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const originalFetch = global.fetch;
test.after(() => { global.fetch = originalFetch; });

function fakeFetch(status, jsonBody) {
    global.fetch = async () => ({
        status,
        ok: status >= 200 && status < 300,
        json: async () => jsonBody,
    });
}

test("checkEmailBreach rejects an invalid email without calling the API", async () => {
    let called = false;
    global.fetch = async () => { called = true; };

    const req = mockReq({ body: { email: "not-an-email" } });
    const res = mockRes();

    await breachController.checkEmailBreach(req, res);

    assert.equal(called, false);
    assert.equal(res.statusCode, 400);
});

test("checkEmailBreach treats a 404 as a clean result", async () => {
    fakeFetch(404, {});

    const req = mockReq({ body: { email: "clean@example.com" } });
    const res = mockRes();

    await breachController.checkEmailBreach(req, res);

    assert.deepEqual(res.body, { found: false, breaches: [] });
});

test("checkEmailBreach surfaces a 429 as a rate-limit error", async () => {
    fakeFetch(429, {});

    const req = mockReq({ body: { email: "busy@example.com" } });
    const res = mockRes();

    await breachController.checkEmailBreach(req, res);

    assert.equal(res.statusCode, 429);
});

test("checkEmailBreach normalizes breach objects into names", async () => {
    fakeFetch(200, { breaches: [[{ breach_id: "Adobe" }, "LinkedIn"]] });

    const req = mockReq({ body: { email: "breached@example.com" } });
    const res = mockRes();

    await breachController.checkEmailBreach(req, res);

    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, { found: true, breaches: ["Adobe", "LinkedIn"] });
});

test("checkEmailBreach returns 500 when the upstream API errors", async () => {
    fakeFetch(503, {});

    const req = mockReq({ body: { email: "oops@example.com" } });
    const res = mockRes();

    await breachController.checkEmailBreach(req, res);

    assert.equal(res.statusCode, 500);
});
