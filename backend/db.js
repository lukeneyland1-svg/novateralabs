const path = require("path");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

const DB_PATH = process.env.NOVATERALABS_DB_PATH || path.join(__dirname, "data", "novateralabs.db");
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
// Nullable: on a brand-new install this table is seeded before any user
// account exists, so ownership gets backfilled below once an owner exists.
try { db.exec("ALTER TABLE automation_tasks ADD COLUMN user_id INTEGER"); } catch (e) {}

db.exec(`
  CREATE TABLE IF NOT EXISTS notified_alerts (
    fingerprint TEXT PRIMARY KEY,
    notified_at TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS account_notified_alerts (
    user_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    notified_at TEXT NOT NULL,
    PRIMARY KEY (user_id, fingerprint)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

// Adds columns needed for password reset and MFA. Safe no-ops if they
// already exist (same pattern as the automation_tasks migration above).
try { db.exec("ALTER TABLE users ADD COLUMN email TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN totp_secret TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN backup_codes TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN is_owner INTEGER NOT NULL DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN api_key TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN subscription_status TEXT NOT NULL DEFAULT 'none'"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN stripe_customer_id TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT"); } catch (e) {}

db.exec(`
  CREATE TABLE IF NOT EXISTS password_resets (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS metrics_snapshots (
    user_id INTEGER PRIMARY KEY,
    cpu_load REAL,
    ram_usage REAL,
    uptime_minutes REAL,
    reported_at TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    type TEXT NOT NULL,
    message TEXT NOT NULL,
    ip TEXT,
    timestamp TEXT NOT NULL
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id)");

// Every account needs its own API key for the agent/data-ingestion pipeline.
// Each row needs a distinct random value, so this can't be a single UPDATE.
for (const user of db.prepare("SELECT id FROM users WHERE api_key IS NULL").all()) {
  db.prepare("UPDATE users SET api_key = ? WHERE id = ?").run(crypto.randomBytes(24).toString("hex"), user.id);
}

// The very first account ever created becomes the owner (idempotent — a
// no-op once an owner is already set). Then attribute any ownerless
// automation tasks (e.g. the demo tasks seeded below, which run before any
// user account exists on a brand-new install) to that owner.
db.prepare("UPDATE users SET is_owner = 1 WHERE id = (SELECT MIN(id) FROM users) AND is_owner = 0").run();
db.prepare("UPDATE automation_tasks SET user_id = (SELECT MIN(id) FROM users) WHERE user_id IS NULL").run();

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
