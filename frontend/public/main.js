const API = "http://localhost:4000";
let token = "";
let currentLogs = [];
let selectedLogId = null;
let liveTimer = null;
const LIVE_INTERVAL_MS = 3000;

async function login() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const msg = document.getElementById("loginMsg");
  const res = await fetch(`${API}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    msg.textContent = "Echec de connexion";
    return;
  }
  const data = await res.json();
  token = data.token;
  document.getElementById("loginCard").classList.add("hidden");
  document.getElementById("app").classList.remove("hidden");
  await loadAll();
  startLiveRefresh();
}

async function apiGet(path) {
  const res = await fetch(`${API}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.json();
}

async function loadDashboard() {
  const d = await apiGet("/dashboard");
  document.getElementById("kpis").innerHTML = `
    <div class="kpi">Total logs: <b>${d.totalLogs}</b></div>
    <div class="kpi">Tickets ouverts: <b>${d.openTickets}</b></div>
    <div class="kpi">Incidents critiques: <b>${d.criticalIncidents}</b></div>
  `;
}

async function loadLogs() {
  currentLogs = await apiGet("/logs?limit=50");
  document.getElementById("logsBody").innerHTML = currentLogs
    .map(
      (l) =>
        `<tr id="log-row-${l.id}" onclick="openLogDetails(${l.id})"><td>${l.id}</td><td>${escapeHtml(l.timestamp)}</td><td>${escapeHtml(l.host)}</td><td>${escapeHtml(l.severity)}</td><td>${escapeHtml(l.source)}</td><td>${escapeHtml(l.message)}</td></tr>`
    )
    .join("");
  if (currentLogs.length > 0 && !currentLogs.some((l) => l.id === selectedLogId)) {
    selectedLogId = currentLogs[0].id;
  }
  highlightSelectedLogRow();
}

async function loadTickets() {
  const tickets = await apiGet("/tickets");
  document.getElementById("ticketsBody").innerHTML = tickets
    .map(
      (t) =>
        `<tr><td>${t.id}</td><td>${t.incident_title}</td><td>${t.status}</td><td>${t.assignee || "-"}</td></tr>`
    )
    .join("");
}

async function loadAuditLogs() {
  const body = document.getElementById("auditBody");
  try {
    const audits = await apiGet("/audit-logs?limit=30");
    if (!Array.isArray(audits)) {
      body.innerHTML = `<tr><td colspan="4">Acces refuse ou erreur.</td></tr>`;
      return;
    }
    body.innerHTML = audits
      .map(
        (a) =>
          `<tr><td>${escapeHtml(a.created_at || "-")}</td><td>${escapeHtml(a.action || "-")}</td><td>${escapeHtml((a.target_type || "-") + ":" + (a.target_id || "-"))}</td><td>${escapeHtml(a.actor_username || "-")}</td></tr>`
      )
      .join("");
  } catch (_e) {
    body.innerHTML = `<tr><td colspan="4">Erreur chargement audit logs.</td></tr>`;
  }
}

async function loadAll() {
  await loadDashboard();
  await loadLogs();
  await loadTickets();
  await loadAuditLogs();
}

function showLogDetails(logId) {
  const log = currentLogs.find((l) => l.id === logId);
  if (!log) return;
  selectedLogId = logId;
  highlightSelectedLogRow();
  const detail = [
    `ID: ${log.id}`,
    `Timestamp: ${log.timestamp}`,
    `Host: ${log.host}`,
    `Event ID: ${log.event_id || "-"}`,
    `Severity: ${log.severity}`,
    `Source: ${log.source}`,
    `Message: ${log.message}`,
    "",
    "Raw:",
    log.raw || "-",
  ].join("\n");
  document.getElementById("logDetail").textContent = detail;
}

function openLogDetails(logId) {
  showLogDetails(logId);
  document.getElementById("menuView").classList.add("hidden");
  document.getElementById("detailView").classList.remove("hidden");
}

function backToMenu() {
  document.getElementById("detailView").classList.add("hidden");
  document.getElementById("menuView").classList.remove("hidden");
}

function highlightSelectedLogRow() {
  const rows = document.querySelectorAll("#logsBody tr");
  rows.forEach((row) => row.classList.remove("selected"));
  const selected = document.getElementById(`log-row-${selectedLogId}`);
  if (selected) selected.classList.add("selected");
}

function startLiveRefresh() {
  if (liveTimer) clearInterval(liveTimer);
  setLiveStatus("Live: on (3s)");
  liveTimer = setInterval(async () => {
    try {
      await loadAll();
      setLiveStatus(`Live: on (maj ${new Date().toLocaleTimeString("fr-FR")})`);
    } catch (_e) {
      setLiveStatus("Live: erreur API");
    }
  }, LIVE_INTERVAL_MS);
}

function setLiveStatus(text) {
  const node = document.getElementById("liveStatus");
  if (node) node.textContent = text;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
