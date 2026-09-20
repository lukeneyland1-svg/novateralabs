const test = require("node:test");
const assert = require("node:assert/strict");

const {
    escapeHtml,
    relativeTime,
    sparkPoints,
    statusPill,
    formatDateTime,
    renderAttackChart,
} = require("../../public/dashboardHelpers");

test("escapeHtml neutralizes HTML-significant characters", () => {
    assert.equal(escapeHtml(`<img src=x onerror="alert(1)">`), "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    assert.equal(escapeHtml("Bob & Alice's <script>"), "Bob &amp; Alice&#39;s &lt;script&gt;");
});

test("escapeHtml handles null/undefined without throwing", () => {
    assert.equal(escapeHtml(null), "");
    assert.equal(escapeHtml(undefined), "");
});

test("relativeTime formats recent, minute, hour, and day-old timestamps", () => {
    const now = Date.now();
    assert.equal(relativeTime(new Date(now - 10_000).toISOString()), "just now");
    assert.equal(relativeTime(new Date(now - 5 * 60_000).toISOString()), "5m ago");
    assert.equal(relativeTime(new Date(now - 3 * 60 * 60_000).toISOString()), "3h ago");
    assert.equal(relativeTime(new Date(now - 2 * 24 * 60 * 60_000).toISOString()), "2d ago");
});

test("sparkPoints maps values into an SVG polyline points string within bounds", () => {
    const points = sparkPoints([0, 50, 100], 3);
    const coords = points.split(" ").map(p => p.split(",").map(Number));

    assert.equal(coords.length, 3);
    for (const [x, y] of coords) {
        assert.ok(x >= 0 && x <= 120);
        assert.ok(y >= 0 && y <= 30);
    }
    // A value of 100 (the max) should sit at the top of the chart (y = 0).
    assert.equal(coords[2][1], 0);
});

test("sparkPoints clamps out-of-range values instead of breaking the chart", () => {
    const points = sparkPoints([-50, 500], 2);
    const coords = points.split(" ").map(p => p.split(",").map(Number));

    assert.equal(coords[0][1], 30); // clamped to 0 -> bottom of chart
    assert.equal(coords[1][1], 0);  // clamped to 100 -> top of chart
});

test("statusPill maps known statuses and defaults unknown ones to paused", () => {
    assert.equal(statusPill("Running"), "success");
    assert.equal(statusPill("Success"), "success");
    assert.equal(statusPill("Failed"), "failed");
    assert.equal(statusPill("Error"), "failed");
    assert.equal(statusPill("Idle"), "paused");
    assert.equal(statusPill(undefined), "paused");
});

test("formatDateTime passes through placeholders and invalid dates unchanged", () => {
    assert.equal(formatDateTime(""), "—");
    assert.equal(formatDateTime("—"), "—");
    assert.equal(formatDateTime("not-a-date"), "not-a-date");
});

test("formatDateTime formats a valid ISO string", () => {
    const formatted = formatDateTime("2026-03-05T14:30:00.000Z");
    assert.equal(typeof formatted, "string");
    assert.notEqual(formatted, "—");
    assert.notEqual(formatted, "2026-03-05T14:30:00.000Z");
});

test("renderAttackChart draws one bar per bucket, scaled to the tallest bucket", () => {
    const svg = renderAttackChart([2, 8, 4]);
    const barCount = (svg.match(/<rect/g) || []).length;

    assert.equal(barCount, 3);
    assert.match(svg, /viewBox="0 0 300 50"/);
});

test("renderAttackChart doesn't divide by zero when every bucket is empty", () => {
    assert.doesNotThrow(() => renderAttackChart([0, 0, 0]));
});
