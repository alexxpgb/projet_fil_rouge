require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const db = require("./db");

const app = express();
const port = process.env.PORT || 4000;
const jwtSecret = process.env.JWT_SECRET || "dev-secret-change-me";
const ingestApiKey = process.env.INGEST_API_KEY || "dev-ingest-key";

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(morgan("dev"));

function auth(requiredRoles = []) {
  return (req, res, next) => {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Token manquant" });
    try {
      const payload = jwt.verify(token, jwtSecret);
      if (requiredRoles.length && !requiredRoles.includes(payload.role)) {
        return res.status(403).json({ error: "Acces refuse" });
      }
      req.user = payload;
      next();
    } catch (_e) {
      return res.status(401).json({ error: "Token invalide" });
    }
  };
}

function detectRule(log) {
  const msg = (log.message || "").toLowerCase();
  if (msg.includes("failed login") || msg.includes("brute force")) {
    return { title: `Suspicion brute force sur ${log.host}`, severity: "high" };
  }
  if (msg.includes("powershell -enc") || msg.includes("mimikatz")) {
    return { title: `Execution suspecte sur ${log.host}`, severity: "critical" };
  }
  return null;
}

app.get("/health", (_req, res) => res.json({ status: "ok" }));

app.post("/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Identifiants invalides" });
  }
  const user = db
    .prepare("SELECT id, username, password_hash, role FROM users WHERE username = ?")
    .get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Identifiants invalides" });
  }
  const token = jwt.sign({ sub: user.id, username: user.username, role: user.role }, jwtSecret, {
    expiresIn: "12h",
  });
  res.json({ token, role: user.role, username: user.username });
});

app.post("/logs/ingest", (req, res) => {
  const apiKey = req.headers["x-api-key"];
  if (apiKey !== ingestApiKey) {
    return res.status(401).json({ error: "API key invalide" });
  }
  const { timestamp, host, event_id, severity, source, message, raw } = req.body || {};
  if (!timestamp || !host || !severity || !source || !message) {
    return res.status(400).json({ error: "Payload log incomplet" });
  }
  const insertLog = db.prepare(
    "INSERT INTO logs (timestamp, host, event_id, severity, source, message, raw) VALUES (?, ?, ?, ?, ?, ?, ?)"
  );
  const result = insertLog.run(timestamp, host, event_id || null, severity, source, message, raw || null);
  const logId = result.lastInsertRowid;

  const rule = detectRule({ host, message });
  if (rule) {
    const now = new Date().toISOString();
    const incidentResult = db
      .prepare(
        "INSERT INTO incidents (title, severity, status, created_at, updated_at, detected_from_log_id) VALUES (?, ?, 'new', ?, ?, ?)"
      )
      .run(rule.title, rule.severity, now, now, logId);
    db.prepare(
      "INSERT INTO tickets (incident_id, status, created_at, updated_at) VALUES (?, 'new', ?, ?)"
    ).run(incidentResult.lastInsertRowid, now, now);
  }

  res.status(201).json({ ok: true, log_id: logId });
});

app.get("/logs", auth(["admin", "analyst"]), (req, res) => {
  const { host, severity, limit = 100 } = req.query;
  let query = "SELECT * FROM logs WHERE 1=1";
  const params = [];
  if (host) {
    query += " AND host = ?";
    params.push(host);
  }
  if (severity) {
    query += " AND severity = ?";
    params.push(severity);
  }
  query += " ORDER BY id DESC LIMIT ?";
  params.push(Number(limit));
  const rows = db.prepare(query).all(...params);
  res.json(rows);
});

app.get("/incidents", auth(["admin", "analyst"]), (_req, res) => {
  const rows = db.prepare("SELECT * FROM incidents ORDER BY id DESC").all();
  res.json(rows);
});

app.get("/tickets", auth(["admin", "analyst"]), (_req, res) => {
  const rows = db
    .prepare(
      `SELECT t.*, i.title as incident_title, u.username as assignee
       FROM tickets t
       JOIN incidents i ON i.id = t.incident_id
       LEFT JOIN users u ON u.id = t.assignee_id
       ORDER BY t.id DESC`
    )
    .all();
  res.json(rows);
});

app.patch("/tickets/:id", auth(["admin", "analyst"]), (req, res) => {
  const id = Number(req.params.id);
  const { status, assignee_id } = req.body || {};
  const allowed = ["new", "in_progress", "closed"];
  if (status && !allowed.includes(status)) {
    return res.status(400).json({ error: "Statut invalide" });
  }
  const existing = db.prepare("SELECT * FROM tickets WHERE id = ?").get(id);
  if (!existing) return res.status(404).json({ error: "Ticket introuvable" });
  const nextStatus = status || existing.status;
  const nextAssignee = assignee_id === undefined ? existing.assignee_id : assignee_id;
  const now = new Date().toISOString();
  db.prepare("UPDATE tickets SET status = ?, assignee_id = ?, updated_at = ? WHERE id = ?").run(
    nextStatus,
    nextAssignee,
    now,
    id
  );
  res.json({ ok: true });
});

app.get("/dashboard", auth(["admin", "analyst"]), (_req, res) => {
  const totalLogs = db.prepare("SELECT COUNT(*) as c FROM logs").get().c;
  const openTickets = db
    .prepare("SELECT COUNT(*) as c FROM tickets WHERE status != 'closed'")
    .get().c;
  const criticalIncidents = db
    .prepare("SELECT COUNT(*) as c FROM incidents WHERE severity = 'critical' AND status != 'closed'")
    .get().c;
  res.json({ totalLogs, openTickets, criticalIncidents });
});

app.listen(port, () => {
  console.log(`SOCket API running on http://localhost:${port}`);
});
