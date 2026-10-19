const fs = require("fs");
const path = require("path");
const db = require("../db");

// Real database backups for the "backup" automation task type. Uses SQLite's
// online backup API (via better-sqlite3), which produces a consistent copy
// even while the live server keeps writing — a plain file copy of the .db
// could catch it mid-write and be corrupt. Only the newest KEEP backups are
// kept so the disk can't fill up over time.
const BACKUP_DIR = process.env.NOVATERALABS_BACKUP_DIR || path.join(__dirname, "..", "data", "backups");
const KEEP = 7;

async function backupDatabase() {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const file = path.join(BACKUP_DIR, `novateralabs-${stamp}.db`);
    await db.backup(file);
    const removed = pruneOldBackups();
    const sizeMb = (fs.statSync(file).size / (1024 * 1024)).toFixed(1);
    return { file, sizeMb, removed };
}

function pruneOldBackups() {
    // Timestamped names sort chronologically, so newest-last after sort().
    const backups = fs.readdirSync(BACKUP_DIR)
        .filter((f) => /^novateralabs-.*\.db$/.test(f))
        .sort();
    const toRemove = backups.slice(0, Math.max(0, backups.length - KEEP));
    for (const f of toRemove) fs.unlinkSync(path.join(BACKUP_DIR, f));
    return toRemove.length;
}

module.exports = { backupDatabase, BACKUP_DIR, KEEP };
