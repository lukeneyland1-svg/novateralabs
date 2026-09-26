const helmet = require("helmet");

// Every source on this site is same-origin, with one exception: style.css
// pulls in Google Fonts via @import (fonts.googleapis.com for the stylesheet,
// which itself references font files on fonts.gstatic.com). Missed this the
// first time around by only grepping the HTML files for external src/href,
// not the CSS — a real CSP violation in production caught it. Everything
// else (scripts, images, fetches) really is same-origin; Stripe Checkout is
// a full top-level page navigation, not an iframe or embed.
// style-src keeps 'unsafe-inline' since the pages use plenty of inline
// style="..." attributes; unlike inline <script>, inline styles can't execute
// arbitrary JS, so this is a standard, low-risk allowance — script-src has no
// such exception.
module.exports = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            imgSrc: ["'self'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
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
