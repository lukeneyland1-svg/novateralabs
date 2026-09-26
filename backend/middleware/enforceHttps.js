// server.js runs one shared Express app behind both a plain HTTP listener
// (port 80) and a TLS listener (port 443) — req.secure reflects which socket
// the request actually came in on. Without this, the Strict-Transport-Security
// header we now send is close to meaningless: a browser that has never
// visited over HTTPS yet has no HSTS policy to enforce, so its very first
// request could still go out over plain HTTP unless something redirects it.
module.exports = (req, res, next) => {
    if (!req.secure) {
        return res.redirect(301, `https://${req.hostname}${req.originalUrl}`);
    }
    next();
};
