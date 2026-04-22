const test = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const fs = require("fs");
const path = require("path");

const testDbPath = path.join(__dirname, "..", "data", "socket.test.db");
if (fs.existsSync(testDbPath)) {
  fs.unlinkSync(testDbPath);
}

process.env.SQLITE_PATH = testDbPath;
process.env.REQUIRE_STRONG_SECRETS = "false";
process.env.JWT_SECRET = "test-jwt-secret-very-long-123456789";
process.env.INGEST_API_KEY = "test-ingest-key-123456";
process.env.BOOTSTRAP_ADMIN_USERNAME = "admin";
process.env.BOOTSTRAP_ADMIN_PASSWORD = "admin123!";

const app = require("../server");

let token = "";

test("refuse login invalide", async () => {
  const res = await request(app).post("/auth/login").send({ username: "admin", password: "bad-pass" });
  assert.equal(res.statusCode, 401);
});

test("autorise login valide", async () => {
  const res = await request(app).post("/auth/login").send({ username: "admin", password: "admin123!" });
  assert.equal(res.statusCode, 200);
  assert.ok(res.body.token);
  token = res.body.token;
});

test("refuse ingestion sans bonne api key", async () => {
  const res = await request(app)
    .post("/logs/ingest")
    .set("x-api-key", "wrong-key")
    .send({
      timestamp: new Date().toISOString(),
      host: "test-host",
      severity: "info",
      source: "test",
      message: "hello",
    });
  assert.equal(res.statusCode, 401);
});

test("accepte ingestion valide", async () => {
  const res = await request(app)
    .post("/logs/ingest")
    .set("x-api-key", "test-ingest-key-123456")
    .send({
      timestamp: new Date().toISOString(),
      host: "test-host",
      event_id: "100",
      severity: "warning",
      source: "test",
      message: "failed login",
      raw: "raw test log",
    });
  assert.equal(res.statusCode, 201);
});

test("retourne audit logs pour admin", async () => {
  const res = await request(app).get("/audit-logs").set("Authorization", `Bearer ${token}`);
  assert.equal(res.statusCode, 200);
  assert.ok(Array.isArray(res.body));
});
