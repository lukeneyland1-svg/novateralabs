module.exports = function requireOwner(req, res, next) {
    if (req.session && req.session.isOwner) {
        return next();
    }
    res.status(403).json({ error: "Not available on this account." });
};
