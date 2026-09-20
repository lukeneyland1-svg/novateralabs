process.env.EMAIL_USER = "novateralabs.test@example.com";
process.env.EMAIL_PASS = "test-pass";

const test = require("node:test");
const assert = require("node:assert/strict");

const contactController = require("../controllers/contactController");
const mailer = require("../services/mailer");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

const originalSendMail = mailer.transporter.sendMail;
test.after(() => { mailer.transporter.sendMail = originalSendMail; });

function fakeSendMail(impl) {
    mailer.transporter.sendMail = impl;
}

test("honeypot field silently succeeds without sending an email", async () => {
    let called = false;
    fakeSendMail(async () => { called = true; });

    const req = mockReq({ body: { name: "Bot", email: "bot@example.com", message: "hi", website: "http://spam.example" } });
    const res = mockRes();

    await contactController.sendContactMessage(req, res);

    assert.equal(called, false);
    assert.deepEqual(res.body, { success: true });
});

test("rejects a request missing required fields", async () => {
    let called = false;
    fakeSendMail(async () => { called = true; });

    const req = mockReq({ body: { name: "", email: "", message: "" } });
    const res = mockRes();

    await contactController.sendContactMessage(req, res);

    assert.equal(called, false);
    assert.equal(res.statusCode, 400);
});

test("rejects an invalid email address", async () => {
    const req = mockReq({ body: { name: "A", email: "not-an-email", message: "hello" } });
    const res = mockRes();

    await contactController.sendContactMessage(req, res);

    assert.equal(res.statusCode, 400);
});

test("rejects an overly long message", async () => {
    const req = mockReq({ body: { name: "A", email: "a@example.com", message: "x".repeat(5001) } });
    const res = mockRes();

    await contactController.sendContactMessage(req, res);

    assert.equal(res.statusCode, 400);
});

test("sends a valid message through the mailer and returns success", async () => {
    let sentWith = null;
    fakeSendMail(async (opts) => { sentWith = opts; });

    const req = mockReq({ body: { name: "Jane", email: "jane@example.com", message: "Hello there" } });
    const res = mockRes();

    await contactController.sendContactMessage(req, res);

    assert.deepEqual(res.body, { success: true });
    assert.equal(sentWith.replyTo, "jane@example.com");
    assert.match(sentWith.subject, /Jane/);
    assert.match(sentWith.text, /Hello there/);
});

test("returns 500 when the mailer fails to send", async () => {
    fakeSendMail(async () => { throw new Error("smtp down"); });

    const req = mockReq({ body: { name: "Jane", email: "jane@example.com", message: "Hello there" } });
    const res = mockRes();

    await contactController.sendContactMessage(req, res);

    assert.equal(res.statusCode, 500);
});
