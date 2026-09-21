const db = require("../db");
const scanner = require("../services/attackSurfaceScanner");

function isValidDomain(target) {
    try {
        const url = new URL(target.startsWith("http") ? target : `https://${target}`);
        return !!url.hostname && url.hostname.includes(".");
    } catch {
        return false;
    }
}

exports.runScan = async (req, res) => {
    try {
        const { target } = req.body;
        if (!target || !isValidDomain(target)) {
            return res.status(400).json({ error: "Please enter a valid domain, e.g. example.com" });
        }

        const result = await scanner.runScan(target);

        db.prepare("UPDATE users SET scan_target = ? WHERE id = ?").run(target, req.session.userId);

        res.json(result);
    } catch (err) {
        if (err.code === "UNSAFE_TARGET") {
            return res.status(400).json({ error: err.message });
        }
        console.error("Scan error:", err);
        res.status(500).json({ error: "Something went wrong running that scan. Please try again later." });
    }
};

exports.getScanTarget = (req, res) => {
    const user = db.prepare("SELECT scan_target FROM users WHERE id = ?").get(req.session.userId);
    res.json({ target: user ? user.scan_target : null });
};
