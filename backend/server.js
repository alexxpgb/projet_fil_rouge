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
const webhookUrl = process.env.WEBHOOK_URL || "";

async function sendWebhook(incident) {
  if (!webhookUrl) return;
  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: `[SOCket ALERTE] ${incident.severity.toUpperCase()}: ${incident.title}`,
        incident,
      }),
    });
  } catch (e) {
    console.error("Webhook failed:", e.message);
  }
}
const jwtSecret = process.env.JWT_SECRET || "dev-secret-change-me";
const ingestApiKey = process.env.INGEST_API_KEY || "dev-ingest-key-very-strong";
const requireStrongSecrets = process.env.REQUIRE_STRONG_SECRETS !== "false";
const maxFailedLoginAttempts = Number(process.env.MAX_FAILED_LOGIN_ATTEMPTS || 5);
const lockMinutes = Number(process.env.LOGIN_LOCK_MINUTES || 15);

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
  const rules = db.prepare("SELECT * FROM detection_rules WHERE enabled = 1").all();
  for (const rule of rules) {
    if (msg.includes(rule.pattern.toLowerCase())) {
      return {
        title: rule.title_template.replace("{{host}}", log.host),
        severity: rule.severity,
      };
    }
  }
  return null;
}

const ruleSchema = z.object({
  name: z.string().min(1).max(100),
  pattern: z.string().min(1).max(200),
  severity: z.enum(["info", "warning", "high", "critical"]),
  title_template: z.string().min(1).max(200),
  enabled: z.boolean().optional().default(true),
});

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
    .prepare("SELECT id, username, password_hash, role, failed_login_attempts, locked_until FROM users WHERE username = ?")
    .get(username);
  if (user?.locked_until && new Date(user.locked_until) > new Date()) {
    auditLog({
      actorUserId: user.id,
      actorUsername: user.username,
      action: "auth_login_blocked_locked",
      targetType: "user",
      targetId: user.id,
    });
    return res.status(423).json({ error: "Compte verrouille temporairement" });
  }
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    if (user) {
      const nextAttempts = (user.failed_login_attempts || 0) + 1;
      let lockUntil = null;
      if (nextAttempts >= maxFailedLoginAttempts) {
        const until = new Date(Date.now() + lockMinutes * 60 * 1000);
        lockUntil = until.toISOString();
      }
      db.prepare(
        "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?"
      ).run(nextAttempts, lockUntil, user.id);
    }
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
  db.prepare("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?").run(user.id);
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
    if (rule.severity === "critical") {
      sendWebhook({ id: incidentResult.lastInsertRowid, title: rule.title, severity: rule.severity });
    }
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

app.get("/rules", auth(["admin", "analyst"]), (req, res) => {
  const rows = db.prepare("SELECT * FROM detection_rules ORDER BY id").all();
  res.json(rows);
});

app.post("/rules", auth(["admin"]), (req, res) => {
  const parsed = ruleSchema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ error: "Payload règle invalide" });
  const { name, pattern, severity, title_template, enabled } = parsed.data;
  const now = new Date().toISOString();
  const result = db.prepare(
    "INSERT INTO detection_rules (name, pattern, severity, title_template, enabled, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).run(name, pattern, severity, title_template, enabled ? 1 : 0, now, req.user.username);
  auditLog({ actorUserId: req.user.sub, actorUsername: req.user.username, action: "rule_created", targetType: "detection_rule", targetId: result.lastInsertRowid, metadata: { name, pattern, severity } });
  res.status(201).json({ ok: true, id: result.lastInsertRowid });
});

app.patch("/rules/:id", auth(["admin"]), (req, res) => {
  const id = Number(req.params.id);
  const parsed = ruleSchema.partial().safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ error: "Payload invalide" });
  const existing = db.prepare("SELECT * FROM detection_rules WHERE id = ?").get(id);
  if (!existing) return res.status(404).json({ error: "Règle introuvable" });
  const next = { ...existing, ...parsed.data };
  db.prepare("UPDATE detection_rules SET name=?, pattern=?, severity=?, title_template=?, enabled=? WHERE id=?")
    .run(next.name, next.pattern, next.severity, next.title_template, next.enabled ? 1 : 0, id);
  auditLog({ actorUserId: req.user.sub, actorUsername: req.user.username, action: "rule_updated", targetType: "detection_rule", targetId: id, metadata: parsed.data });
  res.json({ ok: true });
});

app.get("/metrics/security", auth(["admin"]), async (req, res) => {
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const now = new Date().toISOString();
  const openIncidents   = db.prepare("SELECT COUNT(*) as c FROM incidents WHERE status != 'closed'").get().c;
  const criticalOpen    = db.prepare("SELECT COUNT(*) as c FROM incidents WHERE severity='critical' AND status!='closed'").get().c;
  const failedLoginsH   = db.prepare("SELECT COUNT(*) as c FROM audit_logs WHERE action='auth_login_failed' AND created_at > ?").get(oneHourAgo).c;
  const lockedAccounts  = db.prepare("SELECT COUNT(*) as c FROM users WHERE locked_until IS NOT NULL AND locked_until > ?").get(now).c;
  const openTickets     = db.prepare("SELECT COUNT(*) as c FROM tickets WHERE status != 'closed'").get().c;
  const activeRules     = db.prepare("SELECT COUNT(*) as c FROM detection_rules WHERE enabled = 1").get().c;
  const totalLogs       = await logStore.countLogs();
  res.json({
    timestamp: now,
    incidents:  { open: openIncidents, critical_open: criticalOpen },
    tickets:    { open: openTickets },
    auth:       { failed_logins_last_hour: failedLoginsH, locked_accounts: lockedAccounts },
    logs:       { total: totalLogs },
    detection:  { active_rules: activeRules },
  });
});

app.get("/logs/:id/verify", auth(["admin", "analyst"]), async (req, res) => {
  const result = await logStore.verifyLog(req.params.id);
  if (!result) return res.status(404).json({ error: "Log introuvable" });
  if (!result.match) {
    auditLog({ action: "log_integrity_violation", targetType: "log", targetId: req.params.id });
    return res.status(200).json({ ok: false, ...result, alert: "INTEGRITY VIOLATION — log may have been tampered" });
  }
  res.json({ ok: true, log_id: req.params.id, ...result });
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

if (require.main === module) {
  startServer();
}

module.exports = app;
