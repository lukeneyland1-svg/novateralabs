const helmet = require("helmet");

// Every source on this site is same-origin, with two exceptions:
// 1. style.css pulls in Google Fonts via @import (fonts.googleapis.com for
//    the stylesheet, which itself references font files on
//    fonts.gstatic.com). Missed this the first time around by only grepping
//    the HTML files for external src/href, not the CSS — a real CSP
//    violation in production caught it.
// 2. Cloudflare auto-injects its Web Analytics beacon
//    (static.cloudflareinsights.com/beacon.min.js) into every page at the
//    edge — it's not in this codebase at all, so grepping the repo would
//    never find it. Verified against Cloudflare's own docs: since this is
//    the automatic-injection setup (not a manually added snippet), the
//    beacon reports back to this site's own /cdn-cgi/rum path, which
//    connect-src 'self' already covers — only script-src needs the addition.
// 3. Cloudflare Turnstile (the bot check on login, contact, breach check and
//    forgot-password) loads its script from challenges.cloudflare.com and
//    runs the challenge in an iframe from the same host, so it's allowed in
//    both script-src and frame-src. Its result is posted back to our own
//    API, so connect-src stays 'self'.
// Everything else (images, fetches) really is same-origin; Stripe Checkout
// is a full top-level page navigation, not an iframe or embed.
// style-src keeps 'unsafe-inline' since the pages use plenty of inline
// style="..." attributes; unlike inline <script>, inline styles can't execute
// arbitrary JS, so this is a standard, low-risk allowance — script-src has no
// such exception beyond the explicit hosts above.
module.exports = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://static.cloudflareinsights.com", "https://challenges.cloudflare.com"],
            frameSrc: ["https://challenges.cloudflare.com"],
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
