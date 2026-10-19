// Some automation tasks created before schedules were validated were stored
// in a human-readable form ("Daily @ 02:00", "Weekly @ Sunday 03:00") that
// node-cron can't parse, so the scheduler silently skipped them on every
// boot. This translates those forms into real cron expressions. Returns null
// for anything it doesn't recognize, so unknown strings are left untouched.
const DAYS = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];

function legacyScheduleToCron(schedule) {
    const s = String(schedule).trim().toLowerCase();

    let m = s.match(/^daily\s*@\s*(\d{1,2}):(\d{2})$/);
    if (m) return toCron(m[1], m[2], "*");

    m = s.match(/^weekly\s*@\s*([a-z]+)\s+(\d{1,2}):(\d{2})$/);
    if (m) {
        const day = DAYS.indexOf(m[1]);
        if (day === -1) return null;
        return toCron(m[2], m[3], String(day));
    }

    return null;
}

function toCron(hour, minute, dayOfWeek) {
    const h = Number(hour);
    const min = Number(minute);
    if (h > 23 || min > 59) return null;
    return `${min} ${h} * * ${dayOfWeek}`;
}

module.exports = { legacyScheduleToCron };
