process.env.NOVATERALABS_DB_PATH = ":memory:";
const os = require("os");
const fs = require("fs");
const path = require("path");
process.env.NOVATERALABS_BACKUP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "nl-backup-test-"));

const test = require("node:test");
const assert = require("node:assert/strict");
const cron = require("node-cron");

const db = require("../db");
const scheduler = require("../scheduler");

test.after(() => {
    cron.shutdown();
    fs.rmSync(process.env.NOVATERALABS_BACKUP_DIR, { recursive: true, force: true });
});

test("scheduleTask refuses an invalid cron expression", () => {
    const scheduled = scheduler.scheduleTask({ id: 999, name: "Bad", schedule: "not a cron" });
    assert.equal(scheduled, false);
});

test("scheduleTask registers a valid cron expression", () => {
    const scheduled = scheduler.scheduleTask({ id: 998, name: "Fine", schedule: "0 0 * * *" });
    assert.equal(scheduled, true);
});

test("executeTask runs a 'log' task and records success on the row", async () => {
    const id = db.prepare("INSERT INTO automation_tasks (name, schedule, type) VALUES ('Demo', '0 0 * * *', 'log')").run().lastInsertRowid;
    const task = db.prepare("SELECT * FROM automation_tasks WHERE id = ?").get(id);

    await scheduler.executeTask(task);

    const updated = db.prepare("SELECT * FROM automation_tasks WHERE id = ?").get(task.id);
    assert.equal(updated.status, "success");
    assert.match(updated.last_result, /Executed successfully/);
    assert.notEqual(updated.last_run, "—");
});

test("executeTask runs a 'backup' task: writes a real, openable copy of the database", async () => {
    const task = db.prepare("SELECT * FROM automation_tasks WHERE type = 'backup'").get();

    await scheduler.executeTask(task);

    const updated = db.prepare("SELECT * FROM automation_tasks WHERE id = ?").get(task.id);
    assert.equal(updated.status, "success");
    assert.match(updated.last_result, /Backed up database/);

    const files = fs.readdirSync(process.env.NOVATERALABS_BACKUP_DIR);
    assert.equal(files.length, 1);
    const Database = require("better-sqlite3");
    const copy = new Database(path.join(process.env.NOVATERALABS_BACKUP_DIR, files[0]), { readonly: true });
    assert.ok(copy.prepare("SELECT COUNT(*) AS c FROM automation_tasks").get().c > 0);
    copy.close();
});

test("backups keep only the newest KEEP copies", async () => {
    const { backupDatabase, KEEP } = require("../services/dbBackup");
    const dir = process.env.NOVATERALABS_BACKUP_DIR;
    // Older-dated fakes sort first, so they're the ones that get pruned.
    for (let i = 0; i < KEEP + 2; i++) fs.writeFileSync(path.join(dir, `novateralabs-2000-01-0${i}.db`), "");
    fs.writeFileSync(path.join(dir, "unrelated.txt"), "keep me");

    await backupDatabase();

    const backups = fs.readdirSync(dir).filter((f) => f.startsWith("novateralabs-"));
    assert.equal(backups.length, KEEP);
    assert.ok(backups.some((f) => !f.startsWith("novateralabs-2000")));
    assert.ok(fs.existsSync(path.join(dir, "unrelated.txt")));
});
