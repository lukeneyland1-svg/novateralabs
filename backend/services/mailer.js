const nodemailer = require("nodemailer");

// secrets.js is gitignored and won't exist in CI or a fresh checkout —
// fall back to environment variables so this module can still load there.
let secrets = {};
try {
    secrets = require("../secrets");
} catch {}

const EMAIL_USER = process.env.EMAIL_USER || secrets.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS || secrets.EMAIL_PASS;

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS,
    },
});

module.exports = { transporter, EMAIL_USER };
