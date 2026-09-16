const XPOSED_API = "https://api.xposedornot.com/v1/check-email";

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

exports.checkEmailBreach = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ error: "Please enter a valid email address." });
        }

        const apiRes = await fetch(`${XPOSED_API}/${encodeURIComponent(email)}`);

        // Treat "not found" as a clean, safe result rather than an error.
        if (apiRes.status === 404) {
            return res.json({ found: false, breaches: [] });
        }
        if (apiRes.status === 429) {
            return res.status(429).json({ error: "Too many checks right now. Please try again in a minute." });
        }
        if (!apiRes.ok) {
            throw new Error(`Breach API returned status ${apiRes.status}`);
        }

        const data = await apiRes.json();

        // The upstream API's exact shape has varied across versions, so this
        // normalizes a few possible formats into a flat list of breach names.
        let breaches = data.breaches || [];
        if (Array.isArray(breaches) && breaches.length > 0 && Array.isArray(breaches[0])) {
            breaches = breaches.flat();
        }
        breaches = breaches.map((b) =>
            typeof b === "string" ? b : (b.breach_id || b.name || JSON.stringify(b))
        );

        res.json({ found: breaches.length > 0, breaches });
    } catch (err) {
        console.error("Breach check error:", err);
        res.status(500).json({ error: "Something went wrong checking that email. Please try again later." });
    }
};
