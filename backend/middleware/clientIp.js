// The visitor's real IP address. Behind Cloudflare, the TCP peer is a
// Cloudflare edge server and the visitor's address is in CF-Connecting-IP.
// The origin is also reachable directly, so that header is only trusted when
// the connection really comes from Cloudflare — otherwise anyone could set
// it and pick a fresh "IP" for every request.
//
// Ranges from https://www.cloudflare.com/ips-v4 and /ips-v6 (Oct 2026).
// They change rarely; if Cloudflare adds a range, visitors arriving through
// it are just counted by the edge address until it's added here.
const net = require("net");

const CLOUDFLARE_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
];

const cloudflare = new net.BlockList();
for (const range of CLOUDFLARE_RANGES) {
    const [address, prefix] = range.split("/");
    cloudflare.addSubnet(address, Number(prefix), net.isIPv6(address) ? "ipv6" : "ipv4");
}

// Node reports IPv4 peers on a dual-stack socket as ::ffff:1.2.3.4.
function normalize(address) {
    if (!address) return "";
    return address.startsWith("::ffff:") && net.isIPv4(address.slice(7)) ? address.slice(7) : address;
}

function isCloudflare(address) {
    const type = net.isIPv4(address) ? "ipv4" : net.isIPv6(address) ? "ipv6" : null;
    return type !== null && cloudflare.check(address, type);
}

function clientIp(req) {
    const peer = normalize(req.socket && req.socket.remoteAddress);
    const forwarded = req.headers && req.headers["cf-connecting-ip"];
    if (forwarded && isCloudflare(peer) && net.isIP(forwarded.trim())) {
        return normalize(forwarded.trim());
    }
    return peer;
}

module.exports = clientIp;
module.exports.isCloudflare = isCloudflare;
