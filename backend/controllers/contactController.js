const nodemailer = require("nodemailer");
const { EMAIL_USER, EMAIL_PASS } = require("../secrets");

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS,
    },
});

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

exports.sendContactMessage = async (req, res) => {
    try {
        const { name, email, message, website } = req.body;

        // Honeypot field — real visitors never fill this hidden input.
        // If it's filled, silently pretend success without actually sending anything.
        if (website) {
            return res.status(200).json({ success: true });
        }

        if (!name || !email || !message) {
            return res.status(400).json({ error: "Name, email, and message are all required." });
        }
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: "Please enter a valid email address." });
        }
        if (message.length > 5000) {
            return res.status(400).json({ error: "Message is too long." });
        }

        await transporter.sendMail({
            from: `"NovaTeraLabs Contact Form" <${EMAIL_USER}>`,
            to: EMAIL_USER,
            replyTo: email,
            subject: `New contact form message from ${name}`,
            text: `From: ${name} <${email}>\n\n${message}`,
        });

        res.json({ success: true });
    } catch (err) {
        console.error("Contact form error:", err);
        res.status(500).json({ error: "Something went wrong sending your message. Please try again later." });
    }
};
