const {
  randomBytes,
  scrypt: scryptCallback,
  scryptSync,
  timingSafeEqual,
} = require("node:crypto");
const { promisify } = require("node:util");

const scrypt = promisify(scryptCallback);

function isValidEmail(email) {
  return typeof email === "string"
    && email.length <= 254
    && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(password) {
  return typeof password === "string"
    && password.length >= 12
    && password.length <= 128;
}

async function hashPassword(password) {
  const salt = randomBytes(16);
  const derivedKey = await scrypt(password, salt, 64);
  return `${salt.toString("hex")}:${derivedKey.toString("hex")}`;
}

function hashPasswordSync(password) {
  const salt = randomBytes(16);
  const derivedKey = scryptSync(password, salt, 64);
  return `${salt.toString("hex")}:${derivedKey.toString("hex")}`;
}

async function verifyPassword(password, storedHash) {
  if (typeof password !== "string" || typeof storedHash !== "string") {
    return false;
  }

  const [saltHex, keyHex, extra] = storedHash.split(":");
  if (!saltHex || !keyHex || extra !== undefined || !/^[a-f0-9]+$/i.test(saltHex) || !/^[a-f0-9]+$/i.test(keyHex)) {
    return false;
  }

  const salt = Buffer.from(saltHex, "hex");
  const expected = Buffer.from(keyHex, "hex");
  if (salt.length !== 16 || expected.length !== 64) {
    return false;
  }

  const actual = await scrypt(password, salt, expected.length);
  return timingSafeEqual(actual, expected);
}

function createCsrfToken() {
  return randomBytes(32).toString("base64url");
}

function tokensMatch(expected, actual) {
  if (typeof expected !== "string" || typeof actual !== "string") {
    return false;
  }

  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(actual);
  return expectedBuffer.length === actualBuffer.length
    && timingSafeEqual(expectedBuffer, actualBuffer);
}

module.exports = {
  createCsrfToken,
  hashPassword,
  hashPasswordSync,
  isValidEmail,
  tokensMatch,
  validatePassword,
  verifyPassword,
};
