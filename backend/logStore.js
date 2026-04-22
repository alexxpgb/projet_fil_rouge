const { MongoClient } = require("mongodb");
const db = require("./db");

let mongoClient = null;
let mongoCollection = null;

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
    console.log("LogStore: MongoDB connecte.");
  } catch (error) {
    console.log(`LogStore: echec MongoDB (${error.message}), fallback SQLite.`);
    mongoCollection = null;
  }
}

function getInsertSqlStatement() {
  return db.prepare(
    "INSERT INTO logs (timestamp, host, event_id, severity, source, message, raw) VALUES (?, ?, ?, ?, ?, ?, ?)"
  );
}

async function insertLog(payload) {
  if (mongoCollection) {
    const result = await mongoCollection.insertOne(payload);
    return {
      id: result.insertedId.toString(),
      storage: "mongo",
    };
  }

  const stmt = getInsertSqlStatement();
  const result = stmt.run(
    payload.timestamp,
    payload.host,
    payload.event_id || null,
    payload.severity,
    payload.source,
    payload.message,
    payload.raw || null
  );
  return {
    id: result.lastInsertRowid,
    storage: "sqlite",
  };
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
      storage: "mongo",
    }));
  }

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
  params.push(limit);
  const rows = db.prepare(query).all(...params);
  return rows.map((row) => ({ ...row, storage: "sqlite" }));
}

async function countLogs() {
  if (mongoCollection) {
    return mongoCollection.countDocuments();
  }
  return db.prepare("SELECT COUNT(*) as c FROM logs").get().c;
}

module.exports = {
  initLogStore,
  insertLog,
  getLogs,
  countLogs,
};
