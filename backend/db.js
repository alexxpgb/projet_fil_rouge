const Database = require("better-sqlite3");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");

const dbDir = path.join(__dirname, "data");
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const sqlitePath = process.env.SQLITE_PATH || path.join(dbDir, "socket.db");
const db = new Database(sqlitePath);
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','analyst')),
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT
);

CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  host TEXT NOT NULL,
  event_id TEXT,
  severity TEXT NOT NULL,
  source TEXT NOT NULL,
  message TEXT NOT NULL,
  raw TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('new','in_progress','closed')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  detected_from_log_id INTEGER,
  FOREIGN KEY(detected_from_log_id) REFERENCES logs(id)
);

CREATE TABLE IF NOT EXISTS tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL,
  assignee_id INTEGER,
  status TEXT NOT NULL CHECK(status IN ('new','in_progress','closed')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(incident_id) REFERENCES incidents(id),
  FOREIGN KEY(assignee_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER,
  actor_username TEXT,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT,
  metadata TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(actor_user_id) REFERENCES users(id)
);
`);

function ensureColumn(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!columns.find((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

ensureColumn("users", "failed_login_attempts", "INTEGER NOT NULL DEFAULT 0");
ensureColumn("users", "locked_until", "TEXT");
ensureColumn("logs", "hash", "TEXT");

db.exec(`
CREATE TABLE IF NOT EXISTS detection_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  pattern TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('info','warning','high','critical')),
  title_template TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  created_by TEXT
);
`);

const rulesCount = db.prepare("SELECT COUNT(*) as c FROM detection_rules").get().c;
if (rulesCount === 0) {
  const now = new Date().toISOString();
  const seedRule = db.prepare(
    "INSERT INTO detection_rules (name, pattern, severity, title_template, enabled, created_at, created_by) VALUES (?, ?, ?, ?, 1, ?, 'system')"
  );
  seedRule.run("Brute Force - Failed Login", "failed login", "high", "Suspicion brute force sur {{host}}", now);
  seedRule.run("Brute Force - Keyword", "brute force", "high", "Suspicion brute force sur {{host}}", now);
  seedRule.run("PowerShell Encoded", "powershell -enc", "critical", "Execution suspecte sur {{host}}", now);
  seedRule.run("Mimikatz", "mimikatz", "critical", "Execution suspecte sur {{host}}", now);
}

const bootstrapUsername = process.env.BOOTSTRAP_ADMIN_USERNAME || "";
const bootstrapPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD || "";
if (bootstrapUsername && bootstrapPassword) {
  const exists = db
    .prepare("SELECT id FROM users WHERE username = ?")
    .get(bootstrapUsername);
  if (!exists) {
    const hash = bcrypt.hashSync(bootstrapPassword, 12);
    db.prepare(
      "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)"
    ).run(bootstrapUsername, hash, "admin");
    console.log(`Bootstrap admin cree: ${bootstrapUsername}`);
  }
}

module.exports = db;
