const helmet = require("helmet");

// Every source on this site is same-origin: no external scripts/styles/fonts/
// images, no third-party fetches, and Stripe Checkout is a full top-level
// page navigation (not an iframe or embed) — verified by grepping for any
// external src/href before writing this, not assumed. That lets the policy
// stay tight instead of needing to allowlist a bunch of third-party hosts.
// style-src keeps 'unsafe-inline' since the pages use plenty of inline
// style="..." attributes; unlike inline <script>, inline styles can't execute
// arbitrary JS, so this is a standard, low-risk allowance — script-src has no
// such exception.
module.exports = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'"],
            fontSrc: ["'self'"],
            connectSrc: ["'self'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            frameAncestors: ["'none'"],
        },
    },
    // Nothing on this site is meant to be embedded in a frame anywhere —
    // matches frameAncestors above, kept for older browsers that only
    // understand X-Frame-Options rather than CSP's frame-ancestors.
    frameguard: { action: "deny" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
});
