const test = require("node:test");
const assert = require("node:assert/strict");
const cron = require("node-cron");

const { legacyScheduleToCron } = require("../legacySchedule");

test("converts the exact legacy strings found in production", () => {
    assert.equal(legacyScheduleToCron("Daily @ 02:00"), "0 2 * * *");
    assert.equal(legacyScheduleToCron("Weekly @ Sunday 03:00"), "0 3 * * 0");
});

test("converted schedules are valid node-cron expressions", () => {
    assert.ok(cron.validate(legacyScheduleToCron("Daily @ 23:45")));
    assert.ok(cron.validate(legacyScheduleToCron("weekly @ saturday 7:05")));
});

test("leaves real cron expressions and unrecognized strings alone", () => {
    assert.equal(legacyScheduleToCron("0 2 * * *"), null);
    assert.equal(legacyScheduleToCron("*/15 * * * *"), null);
    assert.equal(legacyScheduleToCron("Weekly @ Funday 03:00"), null);
    assert.equal(legacyScheduleToCron("Daily @ 25:00"), null);
    assert.equal(legacyScheduleToCron("whenever"), null);
});
