const fs = require("node:fs");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const session = require("express-session");

const sampleVendors = [
  ["The Wedding Frames", "Photographer", "Meerut", 18000, "Wedding photography, cinematic films and candid moments."],
  ["Dream Decor Studio", "Decoration", "Meerut", 22000, "Wedding stages, floral setups and themed decor."],
  ["Royal Feast Caterers", "Catering", "Meerut", 650, "Custom menus, live counters and event catering."],
  ["SoundWave Events", "DJ & Sound", "Meerut", 12000, "DJ, sound, lighting and stage production."],
  ["Glow Bridal Studio", "Makeup Artist", "Meerut", 7500, "Bridal, party and engagement makeup services."],
  ["The Grand Garden", "Banquet Hall", "Meerut", 45000, "An elegant venue for weddings and family celebrations."],
];

function createDatabase(databasePath) {
  if (databasePath !== ":memory:") {
    fs.mkdirSync(path.dirname(databasePath), { recursive: true });
  }

  const db = new DatabaseSync(databasePath);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'vendor')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS vendors (
      id INTEGER PRIMARY KEY,
      owner_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      city TEXT NOT NULL,
      contact TEXT NOT NULL,
      phone TEXT NOT NULL,
      price INTEGER NOT NULL CHECK (price >= 0),
      description TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY,
      vendor_id INTEGER NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
      customer TEXT NOT NULL,
      phone TEXT NOT NULL,
      event_date TEXT NOT NULL,
      city TEXT NOT NULL,
      budget INTEGER NOT NULL DEFAULT 0 CHECK (budget >= 0),
      event_type TEXT NOT NULL,
      requirements TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'New' CHECK (status IN ('New', 'Contacted')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      sess TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_vendors_public ON vendors(status, city, category);
    CREATE INDEX IF NOT EXISTS idx_vendors_owner ON vendors(owner_user_id);
    CREATE INDEX IF NOT EXISTS idx_bookings_vendor ON bookings(vendor_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
  `);

  const seed = db.prepare(`
    INSERT INTO vendors (owner_user_id, name, category, city, contact, phone, price, description, status)
    SELECT NULL, ?, ?, ?, 'BookMyEvent sample listing', '0000000000', ?, ?, 'approved'
    WHERE NOT EXISTS (SELECT 1 FROM vendors WHERE owner_user_id IS NULL AND name = ?)
  `);
  db.exec("BEGIN");
  try {
    for (const vendor of sampleVendors) {
      seed.run(...vendor, vendor[0]);
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    db.close();
    throw error;
  }

  return db;
}

function createSqliteSessionStore(db) {
  const Store = session.Store;

  class SqliteSessionStore extends Store {
    constructor(database) {
      super();
      this.database = database;
      this.getStatement = database.prepare("SELECT sess, expires_at FROM sessions WHERE sid = ?");
      this.setStatement = database.prepare(`
        INSERT INTO sessions (sid, sess, expires_at) VALUES (?, ?, ?)
        ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expires_at = excluded.expires_at
      `);
      this.deleteStatement = database.prepare("DELETE FROM sessions WHERE sid = ?");
      this.expireStatement = database.prepare("DELETE FROM sessions WHERE expires_at <= ?");
      this.expireStatement.run(Date.now());
      this.cleanupTimer = setInterval(() => {
        this.expireStatement.run(Date.now());
      }, 60 * 60 * 1000);
      this.cleanupTimer.unref();
    }

    get(sid, callback) {
      try {
        const row = this.getStatement.get(sid);
        if (!row || row.expires_at <= Date.now()) {
          this.deleteStatement.run(sid);
          callback(null, null);
          return;
        }
        callback(null, JSON.parse(row.sess));
      } catch (error) {
        callback(error);
      }
    }

    set(sid, sess, callback) {
      try {
        const expiresAt = sess.cookie?.expires
          ? new Date(sess.cookie.expires).getTime()
          : Date.now() + 8 * 60 * 60 * 1000;
        this.setStatement.run(sid, JSON.stringify(sess), expiresAt);
        callback?.(null);
      } catch (error) {
        callback?.(error);
      }
    }

    touch(sid, sess, callback) {
      this.set(sid, sess, callback);
    }

    destroy(sid, callback) {
      try {
        this.deleteStatement.run(sid);
        callback?.(null);
      } catch (error) {
        callback?.(error);
      }
    }

    close() {
      clearInterval(this.cleanupTimer);
    }
  }

  return new SqliteSessionStore(db);
}

module.exports = { createDatabase, createSqliteSessionStore };
