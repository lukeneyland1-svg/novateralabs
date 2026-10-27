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

function backupName(date) {
    return `novateralabs-${date.toISOString().replace(/[:.]/g, "-")}.db`;
}

function emptyBackupDir() {
    const dir = process.env.NOVATERALABS_BACKUP_DIR;
    for (const f of fs.readdirSync(dir)) fs.rmSync(path.join(dir, f));
    return dir;
}

const DAY = 24 * 60 * 60 * 1000;

test("backups older than KEEP_DAYS are pruned, newer ones and unrelated files are kept", async () => {
    const { backupDatabase, KEEP_DAYS } = require("../services/dbBackup");
    const dir = emptyBackupDir();
    const old = backupName(new Date(Date.now() - (KEEP_DAYS + 1) * DAY));
    const recent = backupName(new Date(Date.now() - (KEEP_DAYS - 1) * DAY));
    fs.writeFileSync(path.join(dir, old), "");
    fs.writeFileSync(path.join(dir, recent), "");
    fs.writeFileSync(path.join(dir, "unrelated.txt"), "keep me");

    const { file, removed } = await backupDatabase();

    assert.equal(removed, 1);
    assert.ok(!fs.existsSync(path.join(dir, old)));
    assert.ok(fs.existsSync(path.join(dir, recent)));
    assert.ok(fs.existsSync(file));
    assert.ok(fs.existsSync(path.join(dir, "unrelated.txt")));
});

test("catchUpMissedBackups runs a backup task whose last scheduled run has no backup", async () => {
    const dir = emptyBackupDir();
    fs.writeFileSync(path.join(dir, backupName(new Date(Date.now() - 2 * DAY))), "");
    const task = db.prepare("SELECT * FROM automation_tasks WHERE type = 'backup'").get();

    await scheduler.catchUpMissedBackups([{ ...task, schedule: "0 2 * * *" }]);

    const backups = fs.readdirSync(dir).filter((f) => f.startsWith("novateralabs-"));
    assert.equal(backups.length, 2);
    assert.equal(db.prepare("SELECT status FROM automation_tasks WHERE id = ?").get(task.id).status, "success");
});

test("catchUpMissedBackups does nothing when a backup already covers the last scheduled run", async () => {
    const dir = emptyBackupDir();
    fs.writeFileSync(path.join(dir, backupName(new Date())), "");
    const task = db.prepare("SELECT * FROM automation_tasks WHERE type = 'backup'").get();

    await scheduler.catchUpMissedBackups([{ ...task, schedule: "0 2 * * *" }, { id: 0, type: "log", schedule: "* * * * *" }]);

    assert.equal(fs.readdirSync(dir).length, 1);
});