module.exports = function requireAuthPage(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    res.redirect("/login.html");
};
