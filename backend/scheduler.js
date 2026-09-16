const cron = require("node-cron");
const { CronExpressionParser } = require("cron-parser");
const db = require("./db");

const scheduledJobs = new Map(); // taskId -> node-cron job instance

function computeNextRun(cronExpression) {
    try {
        const interval = CronExpressionParser.parse(cronExpression);
        return interval.next().toISOString();
    } catch (e) {
        return null;
    }
}

async function executeTask(task) {
    let result = "";
    let status = "Idle";

    try {
        if (task.type === "health_check") {
            const start = Date.now();
            const res = await fetch("https://novateralabs.com", { method: "GET" });
            const ms = Date.now() - start;
            if (res.ok) {
                result = `OK — responded in ${ms}ms`;
                status = "success";
            } else {
                result = `FAILED — status ${res.status}`;
                status = "failed";
            }
        } else {
            // "log" type — safe, purely demonstrative, but genuinely executes on schedule.
            result = `Executed successfully at ${new Date().toISOString()}`;
            status = "success";
        }
    } catch (err) {
        result = `FAILED — ${err.message}`;
        status = "failed";
    }

    const nextRun = computeNextRun(task.schedule);
    db.prepare(`
        UPDATE automation_tasks
        SET status = ?, last_run = ?, next_run = ?, last_result = ?
        WHERE id = ?
    `).run(status, new Date().toISOString(), nextRun || "—", result, task.id);

    console.log(`[scheduler] Ran task "${task.name}": ${result}`);
}

function scheduleTask(task) {
    if (!cron.validate(task.schedule)) {
        console.warn(`[scheduler] Skipping task "${task.name}" — invalid cron expression: "${task.schedule}"`);
        return false;
    }

    // If this task was already scheduled (e.g. being re-registered), stop the old job first.
    if (scheduledJobs.has(task.id)) {
        scheduledJobs.get(task.id).stop();
    }

    const job = cron.schedule(task.schedule, () => executeTask(task));
    scheduledJobs.set(task.id, job);

    const nextRun = computeNextRun(task.schedule);
    if (nextRun) {
        db.prepare("UPDATE automation_tasks SET next_run = ? WHERE id = ?").run(nextRun, task.id);
    }

    return true;
}

function loadAndScheduleAll() {
    const tasks = db.prepare("SELECT * FROM automation_tasks").all();
    let scheduledCount = 0;
    for (const task of tasks) {
        if (scheduleTask(task)) scheduledCount++;
    }
    console.log(`[scheduler] Scheduled ${scheduledCount} of ${tasks.length} automation tasks`);
}

module.exports = { loadAndScheduleAll, scheduleTask, executeTask };
