const nodemailer = require("nodemailer");
const { EMAIL_USER, EMAIL_PASS } = require("../secrets");

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS,
    },
});

module.exports = { transporter, EMAIL_USER };
