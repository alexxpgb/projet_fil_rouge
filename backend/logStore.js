const { MongoClient } = require("mongodb");
const crypto = require("crypto");
const db = require("./db");

let mongoClient = null;
let mongoCollection = null;

function hashLog(payload) {
  const stable = JSON.stringify({
    timestamp: payload.timestamp,
    host: payload.host,
    event_id: payload.event_id || null,
    severity: payload.severity,
    source: payload.source,
    message: payload.message,
    raw: payload.raw || null,
  });
  return crypto.createHash("sha256").update(stable).digest("hex");
}

async function initLogStore() {
  const mongoUri = process.env.MONGO_URI || "";
  const mongoDbName = process.env.MONGO_DB_NAME || "socket";
  const mongoCollectionName = process.env.MONGO_LOG_COLLECTION || "logs";

  if (!mongoUri) {
    console.log("LogStore: MongoDB non configure, fallback SQLite.");
    return;
  }

  try {
    mongoClient = new MongoClient(mongoUri, {
      serverSelectionTimeoutMS: 3000,
      connectTimeoutMS: 3000,
    });
    await mongoClient.connect();
    const mongoDb = mongoClient.db(mongoDbName);
    mongoCollection = mongoDb.collection(mongoCollectionName);
    await mongoCollection.createIndex({ timestamp: -1 });
    await mongoCollection.createIndex({ host: 1, severity: 1 });
    await mongoCollection.createIndex({ hash: 1 });
    console.log("LogStore: MongoDB connecte.");
  } catch (error) {
    console.log(`LogStore: echec MongoDB (${error.message}), fallback SQLite.`);
    mongoCollection = null;
  }
}

async function insertLog(payload) {
  const hash = hashLog(payload);

  if (mongoCollection) {
    const result = await mongoCollection.insertOne({ ...payload, hash });
    return { id: result.insertedId.toString(), storage: "mongo", hash };
  }

  const stmt = db.prepare(
    "INSERT INTO logs (timestamp, host, event_id, severity, source, message, raw, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  );
  const result = stmt.run(
    payload.timestamp,
    payload.host,
    payload.event_id || null,
    payload.severity,
    payload.source,
    payload.message,
    payload.raw || null,
    hash
  );
  return { id: result.lastInsertRowid, storage: "sqlite", hash };
}

async function verifyLog(id) {
  if (mongoCollection) {
    const { ObjectId } = require("mongodb");
    let oid;
    try { oid = new ObjectId(id); } catch { return null; }
    const doc = await mongoCollection.findOne({ _id: oid });
    if (!doc) return null;
    const { hash: storedHash, ...rest } = doc;
    delete rest._id;
    const computed = hashLog(rest);
    return { stored_hash: storedHash, computed_hash: computed, match: storedHash === computed };
  }

  const row = db.prepare("SELECT * FROM logs WHERE id = ?").get(id);
  if (!row) return null;
  const { hash: storedHash, id: _id, ...rest } = row;
  const computed = hashLog(rest);
  return { stored_hash: storedHash, computed_hash: computed, match: storedHash === computed };
}

async function getLogs({ host, severity, limit }) {
  if (mongoCollection) {
    const query = {};
    if (host) query.host = host;
    if (severity) query.severity = severity;
    const rows = await mongoCollection.find(query).sort({ timestamp: -1 }).limit(limit).toArray();
    return rows.map((row) => ({
      id: row._id.toString(),
      timestamp: row.timestamp,
      host: row.host,
      event_id: row.event_id || null,
      severity: row.severity,
      source: row.source,
      message: row.message,
      raw: row.raw || null,
      hash: row.hash || null,
      storage: "mongo",
    }));
  }

  let query = "SELECT * FROM logs WHERE 1=1";
  const params = [];
  if (host) { query += " AND host = ?"; params.push(host); }
  if (severity) { query += " AND severity = ?"; params.push(severity); }
  query += " ORDER BY id DESC LIMIT ?";
  params.push(limit);
  return db.prepare(query).all(...params).map((row) => ({ ...row, storage: "sqlite" }));
}

async function countLogs() {
  if (mongoCollection) return mongoCollection.countDocuments();
  return db.prepare("SELECT COUNT(*) as c FROM logs").get().c;
}

module.exports = { initLogStore, insertLog, verifyLog, getLogs, countLogs };
