const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

const DB_PATH = path.join(__dirname, "data", "novateralabs.db");
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS automation_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    schedule TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Idle',
    last_run TEXT DEFAULT '—',
    next_run TEXT DEFAULT '—',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

// Adds columns needed for real execution. Safe no-ops if they already exist
// (this lets the same file work whether the table is brand new or already had data).
try { db.exec("ALTER TABLE automation_tasks ADD COLUMN type TEXT NOT NULL DEFAULT 'log'"); } catch (e) {}
try { db.exec("ALTER TABLE automation_tasks ADD COLUMN last_result TEXT DEFAULT ''"); } catch (e) {}

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

const taskCount = db.prepare("SELECT COUNT(*) AS c FROM automation_tasks").get().c;
if (taskCount === 0) {
  const seed = db.prepare(`
    INSERT INTO automation_tasks (name, schedule, type, status, last_run, next_run)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  seed.run("Nightly Backup", "0 2 * * *", "log", "Idle", "—", "—");
  seed.run("Site Health Check", "*/15 * * * *", "health_check", "Idle", "—", "—");
}

const userCount = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
if (userCount === 0) {
  // This block only ever runs on a completely fresh database — if you're
  // reading this on an already-set-up server, your real account is untouched.
  console.log("[db] No users found — an admin account will need to be created via scripts/set-password.js");
}

module.exports = db;
