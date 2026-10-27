const fs = require("fs");
const path = require("path");
const db = require("../db");

// Real database backups for the "backup" automation task type. Uses SQLite's
// online backup API (via better-sqlite3), which produces a consistent copy
// even while the live server keeps writing — a plain file copy of the .db
// could catch it mid-write and be corrupt. Backups older than KEEP_DAYS are
// pruned so the disk can't fill up over time.
const BACKUP_DIR = process.env.NOVATERALABS_BACKUP_DIR || path.join(__dirname, "..", "data", "backups");
const KEEP_DAYS = 14;

// novateralabs-2026-10-27T02-23-33-962Z.db -> Date. The timestamp is read
// from the name rather than the file's mtime so a copied or restored backup
// keeps its real age.
const NAME_RE = /^novateralabs-(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z\.db$/;

function backupTime(fileName) {
    const m = NAME_RE.exec(fileName);
    if (!m) return null;
    const t = new Date(`${m[1]}T${m[2]}:${m[3]}:${m[4]}.${m[5]}Z`);
    return isNaN(t.getTime()) ? null : t;
}

function listBackups() {
    if (!fs.existsSync(BACKUP_DIR)) return [];
    return fs.readdirSync(BACKUP_DIR)
        .map((name) => ({ name, time: backupTime(name) }))
        .filter((b) => b.time)
        .sort((a, b) => a.time - b.time);
}

function latestBackupTime() {
    const backups = listBackups();
    return backups.length ? backups[backups.length - 1].time : null;
}

async function backupDatabase() {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const file = path.join(BACKUP_DIR, `novateralabs-${stamp}.db`);
    await db.backup(file);
    const removed = pruneOldBackups(path.basename(file));
    const sizeMb = (fs.statSync(file).size / (1024 * 1024)).toFixed(1);
    return { file, sizeMb, removed };
}

function pruneOldBackups(justWritten) {
    const cutoff = Date.now() - KEEP_DAYS * 24 * 60 * 60 * 1000;
    // Never remove the backup that was just written, even if the clock is off.
    const toRemove = listBackups().filter((b) => b.time.getTime() < cutoff && b.name !== justWritten);
    for (const b of toRemove) fs.unlinkSync(path.join(BACKUP_DIR, b.name));
    return toRemove.length;
}

module.exports = { backupDatabase, latestBackupTime, BACKUP_DIR, KEEP_DAYS };
