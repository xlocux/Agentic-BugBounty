"use strict";

/**
 * identity.js — operative identity management for target registrations.
 *
 * Generates and persists fake identities per target+role.
 * Email scheme: {base}+{target}.{role}@{domain}
 * Example:      xlocux+acme.victim@gmail.com
 *
 * Password: single shared password from env OPERATIVE_PASSWORD.
 * Stored in DB as AES-256-CBC encrypted blob (key = OPERATIVE_ENC_KEY).
 * If no enc key configured, stored as plaintext with a warning.
 *
 * Usage:
 *   const id = require("./identity");
 *   const victim = await id.getOrCreate(db, targetHandle, targetId, "victim");
 *   // { role, email, username, first_name, last_name, password, ... }
 */

const crypto = require("node:crypto");

// ── Config ────────────────────────────────────────────────────────────────────

function getBaseEmail() {
  const raw = process.env.OPERATIVE_BASE_EMAIL || "";
  if (!raw) throw new Error("OPERATIVE_BASE_EMAIL not set in .env");
  return raw.trim().toLowerCase();
}

function getPassword() {
  return process.env.OPERATIVE_PASSWORD || "BugB0unty2026!";
}

function getEncKey() {
  return process.env.OPERATIVE_ENC_KEY || null;
}

// ── Encryption ────────────────────────────────────────────────────────────────

function encrypt(plaintext) {
  const key = getEncKey();
  if (!key) return plaintext; // no key → store plaintext

  // Derive 32-byte key from env string
  const keyBuf = crypto.createHash("sha256").update(key).digest();
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", keyBuf, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return `enc:${iv.toString("hex")}:${enc.toString("hex")}`;
}

function decrypt(stored) {
  if (!stored.startsWith("enc:")) return stored; // plaintext

  const key = getEncKey();
  if (!key) return ""; // can't decrypt without key

  const parts  = stored.split(":");
  const keyBuf = crypto.createHash("sha256").update(key).digest();
  const iv     = Buffer.from(parts[1], "hex");
  const enc    = Buffer.from(parts[2], "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", keyBuf, iv);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
}

// ── Fake data generators ──────────────────────────────────────────────────────

const FIRST_NAMES = [
  "Alex","Jordan","Morgan","Taylor","Casey","Riley","Avery","Quinn",
  "Cameron","Dakota","Skyler","Reese","Peyton","Finley","Hayden"
];

const LAST_NAMES = [
  "Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis",
  "Wilson","Moore","Anderson","Taylor","Thomas","Jackson","White"
];

function randomChoice(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateIdentityData(baseEmail, targetHandle, role) {
  const [localPart, domain] = baseEmail.split("@");
  const tag     = `${targetHandle.toLowerCase().replace(/[^a-z0-9]/g, "")}.${role}`;
  const email   = `${localPart}+${tag}@${domain}`;

  const firstName = randomChoice(FIRST_NAMES);
  const lastName  = randomChoice(LAST_NAMES);
  const year      = randomInt(1980, 2000);
  const month     = String(randomInt(1, 12)).padStart(2, "0");
  const day       = String(randomInt(1, 28)).padStart(2, "0");
  const birthDate = `${year}-${month}-${day}`;

  // Username: firstname + random 4-digit suffix
  const username = `${firstName.toLowerCase()}${randomInt(1000, 9999)}`;

  return {
    role,
    email,
    username,
    first_name:  firstName,
    last_name:   lastName,
    birth_date:  birthDate,
    phone:       null, // not generated — too risky to use fake phone numbers
    extra:       {
      full_name:    `${firstName} ${lastName}`,
      display_name: `${firstName} ${lastName}`,
      company:      "Freelance",
      country:      "US",
      timezone:     "America/New_York"
    }
  };
}

// ── Public API ────────────────────────────────────────────────────────────────

const VALID_ROLES = ["victim", "attacker", "admin", "reviewer"];

/**
 * Get existing identity or create a new one for target+role.
 * Returns the identity with decrypted password.
 *
 * @param {object} db            — opened SQLite DB
 * @param {string} targetHandle  — e.g. "acme"
 * @param {number} targetId      — DB target ID
 * @param {string} role          — victim | attacker | admin | reviewer
 * @returns {object}
 */
function getOrCreate(db, targetHandle, targetId, role) {
  if (!VALID_ROLES.includes(role)) {
    throw new Error(`Invalid role: ${role}. Must be one of: ${VALID_ROLES.join(", ")}`);
  }

  const { upsertIdentity, getIdentity } = require("./db");

  // Return existing
  const existing = getIdentity(db, targetId, role);
  if (existing) {
    return { ...existing, password: decrypt(existing.password_enc) };
  }

  // Generate new
  const baseEmail = getBaseEmail();
  const password  = getPassword();
  const data      = generateIdentityData(baseEmail, targetHandle, role);

  const row = upsertIdentity(db, targetId, {
    ...data,
    password_enc: encrypt(password)
  });

  return { ...row, password, extra: data.extra };
}

/**
 * Get all identities for a target (with decrypted passwords).
 */
function getAll(db, targetId) {
  const { getIdentities } = require("./db");
  return getIdentities(db, targetId).map((r) => ({
    ...r,
    password: decrypt(r.password_enc)
  }));
}

/**
 * Print identity card to stdout (for manual registration).
 */
function printCard(identity) {
  const lines = [
    "┌─────────────────────────────────────────────┐",
    `│  OPERATIVE IDENTITY — ${identity.role.toUpperCase().padEnd(19)}│`,
    "├─────────────────────────────────────────────┤",
    `│  Email:      ${identity.email.padEnd(31)}│`,
    `│  Username:   ${identity.username.padEnd(31)}│`,
    `│  Password:   ${identity.password.padEnd(31)}│`,
    `│  Name:       ${(identity.first_name + " " + identity.last_name).padEnd(31)}│`,
    `│  Birth:      ${(identity.birth_date || "—").padEnd(31)}│`,
    "└─────────────────────────────────────────────┘"
  ];
  console.log(lines.join("\n"));
}

/**
 * Ensure all standard roles exist for a target.
 * Creates victim + attacker identities by default.
 */
function ensureIdentities(db, targetHandle, targetId, roles = ["victim", "attacker"]) {
  return roles.map((role) => getOrCreate(db, targetHandle, targetId, role));
}

module.exports = {
  getOrCreate,
  getAll,
  ensureIdentities,
  printCard,
  decrypt,
  VALID_ROLES
};
