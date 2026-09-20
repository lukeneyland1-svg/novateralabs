// Requiring securityController schedules a real background timer (to poll
// log files every 10s) as a side effect. Capture that timer's handle so we
// can cancel it below — otherwise the test process never exits.
const originalSetInterval = global.setInterval;
let capturedInterval;
global.setInterval = (fn, ms, ...args) => {
    capturedInterval = originalSetInterval(fn, ms, ...args);
    return capturedInterval;
};

const test = require("node:test");
const assert = require("node:assert/strict");

const securityController = require("../controllers/securityController");
const { mockReq, mockRes } = require("../test-helpers/mockExpress");

global.setInterval = originalSetInterval;
test.after(() => clearInterval(capturedInterval));

const { classifyWindowsType, classifyLinuxLine, extractIP, parseLinuxLine, alertEmitter, setCache } = securityController._test;

function alert(overrides = {}) {
    return {
        source: "linux",
        type: "Auth Log",
        severity: "critical",
        message: "Failed password for root",
        ip: "10.0.0.1",
        timestamp: "2026-01-01T00:00:00.000Z",
        ...overrides,
    };
}

test("classifyLinuxLine flags brute-force and break-in signatures as critical", () => {
    assert.equal(classifyLinuxLine("Failed password for root from 10.0.0.1"), "critical");
    assert.equal(classifyLinuxLine("authentication failure for invalid user"), "critical");
    assert.equal(classifyLinuxLine("POSSIBLE BREAK-IN ATTEMPT!"), "critical");
});

test("classifyLinuxLine flags connection-level oddities as high", () => {
    assert.equal(classifyLinuxLine("Connection closed by 10.0.0.1 port 51000"), "high");
    assert.equal(classifyLinuxLine("Disconnected from user root 10.0.0.1"), "high");
});

test("classifyLinuxLine flags routine successful actions as medium", () => {
    assert.equal(classifyLinuxLine("Accepted password for root from 10.0.0.1"), "medium");
    assert.equal(classifyLinuxLine("pam_unix(sudo:session): session opened for user root"), "medium");
});

test("classifyLinuxLine defaults to low for anything unrecognized", () => {
    assert.equal(classifyLinuxLine("Server listening on 0.0.0.0 port 22"), "low");
});

test("classifyWindowsType mirrors the same four severity tiers", () => {
    assert.equal(classifyWindowsType("Account Failed Logon"), "critical");
    assert.equal(classifyWindowsType("Access Blocked"), "high");
    assert.equal(classifyWindowsType("Successful Logon"), "medium");
    assert.equal(classifyWindowsType("Routine Heartbeat"), "low");
    assert.equal(classifyWindowsType(null), "low");
});

test("extractIP finds the first IPv4 address in a string", () => {
    assert.equal(extractIP("Failed login from 192.168.1.5 port 22"), "192.168.1.5");
    assert.equal(extractIP("no ip address here"), null);
    assert.equal(extractIP(null), null);
});

test("parseLinuxLine splits date, message, and IP out of a real auth.log line", () => {
    const line = "May 16 09:41:01 hostname sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2";
    const parsed = parseLinuxLine(line);

    assert.equal(parsed.message, "Failed password for root from 10.0.0.5 port 22 ssh2");
    assert.equal(parsed.ip, "10.0.0.5");
    assert.equal(parsed.severity, "critical");
    assert.equal(parsed.timestamp, new Date("May 16 09:41:01").toISOString());
});

test("parseLinuxLine returns null for a blank line", () => {
    assert.equal(parseLinuxLine("   "), null);
});

test("getSecurityEvents returns the cached alerts as-is with no filters", async () => {
    setCache([alert({ severity: "critical" }), alert({ severity: "low" })]);

    const req = mockReq({ query: {} });
    const res = mockRes();
    await securityController.getSecurityEvents(req, res);

    assert.equal(res.body.length, 2);
});

test("getSecurityEvents filters by severity and source", async () => {
    setCache([
        alert({ severity: "critical", source: "linux" }),
        alert({ severity: "low", source: "linux" }),
        alert({ severity: "critical", source: "windows" }),
    ]);

    const req = mockReq({ query: { severity: "critical", source: "linux" } });
    const res = mockRes();
    await securityController.getSecurityEvents(req, res);

    assert.equal(res.body.length, 1);
    assert.equal(res.body[0].source, "linux");
});

test("getSecurityEvents respects the limit query param", async () => {
    setCache([alert(), alert(), alert()]);

    const req = mockReq({ query: { limit: "2" } });
    const res = mockRes();
    await securityController.getSecurityEvents(req, res);

    assert.equal(res.body.length, 2);
});

test("streamSecurityEvents writes the current cache immediately, then pushes new alerts", () => {
    setCache([alert({ message: "initial" })]);

    let closeHandler;
    const req = { on: (event, cb) => { if (event === "close") closeHandler = cb; } };
    const res = mockRes();

    securityController.streamSecurityEvents(req, res);

    assert.equal(res.headers["Content-Type"], "text/event-stream");
    assert.match(res.written, /"message":"initial"/);

    alertEmitter.emit("alerts", [alert({ message: "pushed" })]);
    assert.match(res.written, /"message":"pushed"/);

    const lengthBeforeClose = res.written.length;
    closeHandler();
    alertEmitter.emit("alerts", [alert({ message: "should-not-appear" })]);
    assert.equal(res.written.length, lengthBeforeClose);
});
