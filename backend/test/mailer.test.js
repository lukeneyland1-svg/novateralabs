process.env.EMAIL_USER = "test@example.com";
process.env.EMAIL_PASS = "test-pass";

const test = require("node:test");
const assert = require("node:assert/strict");

const mailer = require("../services/mailer");

test("mailer loads even without secrets.js and prefers env vars for credentials", () => {
    assert.equal(typeof mailer.transporter.sendMail, "function");
    assert.equal(mailer.EMAIL_USER, "test@example.com");
});
