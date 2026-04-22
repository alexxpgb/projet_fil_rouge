require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const { z } = require("zod");
const db = require("./db");
const logStore = require("./logStore");

const app = express();
const port = process.env.PORT || 4000;
const jwtSecret = process.env.JWT_SECRET || "dev-secret-change-me";
const ingestApiKey = process.env.INGEST_API_KEY || "dev-ingest-key";
const requireStrongSecrets = process.env.REQUIRE_STRONG_SECRETS !== "false";

app.use(helmet());
const allowedOrigin = process.env.CORS_ORIGIN || "http://localhost:8080";
app.use(cors({ origin: allowedOrigin }));
app.use(express.json({ limit: "1mb" }));
app.use(morgan("dev"));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Trop de tentatives de connexion. Reessaye plus tard." },
});

const ingestLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Trop d'envois de logs. Ralentis le flux." },
});

const loginSchema = z.object({
  username: z.string().min(3).max(50),
  password: z.string().min(8).max(200),
});

const ingestLogSchema = z.object({
  timestamp: z.string().min(5).max(80),
  host: z.string().min(1).max(120),
  event_id: z.union([z.string(), z.number()]).optional().nullable(),
  severity: z.enum(["info", "warning", "high", "critical"]),
  source: z.string().min(1).max(120),
  message: z.string().min(1).max(5000),
  raw: z.string().max(20000).optional().nullable(),
});

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

function auditLog({ actorUserId = null, actorUsername = null, action, targetType, targetId = null, metadata = null }) {
  const createdAt = new Date().toISOString();
  db.prepare(
    "INSERT INTO audit_logs (actor_user_id, actor_username, action, target_type, target_id, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).run(
    actorUserId,
    actorUsername,
    action,
    targetType,
    targetId ? String(targetId) : null,
    metadata ? JSON.stringify(metadata) : null,
    createdAt
  );
}

app.get("/health", (_req, res) => res.json({ status: "ok" }));

app.post("/auth/login", loginLimiter, (req, res) => {
  const parsed = loginSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ error: "Payload login invalide" });
  }
  const { username, password } = parsed.data;
  const user = db
    .prepare("SELECT id, username, password_hash, role FROM users WHERE username = ?")
    .get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    auditLog({
      action: "auth_login_failed",
      targetType: "user",
      targetId: username,
      metadata: { reason: "invalid_credentials" },
    });
    return res.status(401).json({ error: "Identifiants invalides" });
  }
  const token = jwt.sign({ sub: user.id, username: user.username, role: user.role }, jwtSecret, {
    expiresIn: "12h",
  });
  auditLog({
    actorUserId: user.id,
    actorUsername: user.username,
    action: "auth_login_success",
    targetType: "user",
    targetId: user.id,
  });
  res.json({ token, role: user.role, username: user.username });
});

app.post("/logs/ingest", ingestLimiter, async (req, res) => {
  const apiKey = req.headers["x-api-key"];
  if (apiKey !== ingestApiKey) {
    auditLog({
      action: "log_ingest_denied",
      targetType: "log",
      metadata: { reason: "bad_api_key", sourceIp: req.ip },
    });
    return res.status(401).json({ error: "API key invalide" });
  }
  const parsed = ingestLogSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ error: "Payload log invalide" });
  }
  const { timestamp, host, event_id, severity, source, message, raw } = parsed.data;
  let inserted;
  try {
    inserted = await logStore.insertLog({
      timestamp,
      host,
      event_id: event_id || null,
      severity,
      source,
      message,
      raw: raw || null,
    });
  } catch (error) {
    return res.status(500).json({ error: `Erreur stockage log: ${error.message}` });
  }
  const logId = inserted.id;

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
    auditLog({
      action: "incident_auto_created",
      targetType: "incident",
      targetId: incidentResult.lastInsertRowid,
      metadata: { logId, severity: rule.severity, title: rule.title },
    });
  }

  res.status(201).json({ ok: true, log_id: logId, storage: inserted.storage });
});

app.get("/logs", auth(["admin", "analyst"]), async (req, res) => {
  const { host, severity, limit = 100 } = req.query;
  const rows = await logStore.getLogs({
    host: host || undefined,
    severity: severity || undefined,
    limit: Number(limit),
  });
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
  auditLog({
    actorUserId: req.user.sub,
    actorUsername: req.user.username,
    action: "ticket_updated",
    targetType: "ticket",
    targetId: id,
    metadata: { status: nextStatus, assignee_id: nextAssignee },
  });
  res.json({ ok: true });
});

app.get("/audit-logs", auth(["admin"]), (req, res) => {
  const limit = Math.min(Number(req.query.limit || 100), 500);
  const rows = db
    .prepare("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?")
    .all(limit);
  res.json(rows);
});

app.get("/dashboard", auth(["admin", "analyst"]), async (_req, res) => {
  const totalLogs = await logStore.countLogs();
  const openTickets = db
    .prepare("SELECT COUNT(*) as c FROM tickets WHERE status != 'closed'")
    .get().c;
  const criticalIncidents = db
    .prepare("SELECT COUNT(*) as c FROM incidents WHERE severity = 'critical' AND status != 'closed'")
    .get().c;
  res.json({ totalLogs, openTickets, criticalIncidents });
});

async function startServer() {
  if (requireStrongSecrets) {
    if (jwtSecret.length < 24 || ingestApiKey.length < 16) {
      console.error("Secrets trop faibles. Configure JWT_SECRET>=24 chars et INGEST_API_KEY>=16 chars.");
      process.exit(1);
    }
  }
  await logStore.initLogStore();
  app.listen(port, () => {
    console.log(`SOCket API running on http://localhost:${port}`);
  });
}

startServer();
