const db = require("../db");
const cron = require("node-cron");
const scheduler = require("../scheduler");

exports.getAutomationTasks = (req, res) => {
    try {
        const rows = db.prepare(`
            SELECT id, name, schedule, type, status, last_run AS lastRun, next_run AS nextRun, last_result AS lastResult
            FROM automation_tasks
            ORDER BY id DESC
        `).all();
        res.json({ tasks: rows });
    } catch (err) {
        console.error("Automation API error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

exports.createAutomationTask = (req, res) => {
    try {
        const { name, schedule, type } = req.body;
        if (!name || !schedule) {
            return res.status(400).json({ error: "Name and schedule are required." });
        }
        if (!cron.validate(schedule)) {
            return res.status(400).json({
                error: "Schedule must be a valid 5-field cron expression, e.g. \"0 2 * * *\" for daily at 2am.",
            });
        }
        const taskType = type === "health_check" ? "health_check" : "log";

        const result = db.prepare(`
            INSERT INTO automation_tasks (name, schedule, type, status, last_run, next_run)
            VALUES (?, ?, ?, 'Idle', '—', '—')
        `).run(name, schedule, taskType);

        const task = db.prepare(`
            SELECT id, name, schedule, type, status, last_run AS lastRun, next_run AS nextRun, last_result AS lastResult
            FROM automation_tasks WHERE id = ?
        `).get(result.lastInsertRowid);

        scheduler.scheduleTask({ id: task.id, name: task.name, schedule: task.schedule, type: task.type });

        res.status(201).json({ task });
    } catch (err) {
        console.error("Automation create error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};
