require("dotenv").config();

const path = require("node:path");
const { createApp } = require("./app");
const { createDatabase } = require("./database");

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "127.0.0.1";
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be a valid TCP port.");
}

if (process.env.NODE_ENV === "production"
  && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  throw new Error("Set a random SESSION_SECRET of at least 32 characters in production.");
}

const sessionSecret = process.env.SESSION_SECRET || require("node:crypto").randomBytes(48).toString("hex");
const adminEmail = process.env.ADMIN_EMAIL?.trim().toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD;
if (Boolean(adminEmail) !== Boolean(adminPassword)) {
  throw new Error("Set both ADMIN_EMAIL and ADMIN_PASSWORD to bootstrap the first admin.");
}

const databasePath = process.env.DATABASE_PATH
  ? path.resolve(process.env.DATABASE_PATH)
  : path.join(__dirname, "..", "data", "bookmyevent.sqlite");
const db = createDatabase(databasePath);
const app = createApp({
  db,
  sessionSecret,
  adminEmail,
  adminPassword,
  production: process.env.NODE_ENV === "production",
  trustProxy: process.env.TRUST_PROXY === "1",
});

const server = app.listen(port, host, () => {
  console.log(`BookMyEvent is running at http://${host}:${port}`);
  if (!adminEmail) {
    console.warn("No admin account configured. Set ADMIN_EMAIL and ADMIN_PASSWORD, then restart.");
  }
  if (process.env.NODE_ENV !== "production") {
    console.warn("Development mode only. Do not expose this server publicly.");
  }
});

function shutdown() {
  server.close(() => {
    app.locals.sessionStore.close();
    db.close();
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
