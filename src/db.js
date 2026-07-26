import { DatabaseSync } from 'node:sqlite';
import { randomUUID, scryptSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.DATA_DIR || join(__dirname, '..', 'data');
mkdirSync(DATA_DIR, { recursive: true });

export const db = new DatabaseSync(join(DATA_DIR, 'app.db'));

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id             TEXT PRIMARY KEY,
    role           TEXT NOT NULL,
    email          TEXT NOT NULL UNIQUE,
    passwordHash   TEXT NOT NULL,
    fullName       TEXT,
    phone          TEXT,
    clinic         TEXT,
    specialization TEXT,
    city           TEXT,
    status         TEXT,
    createdAt      INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token     TEXT PRIMARY KEY,
    userId    TEXT NOT NULL,
    createdAt INTEGER NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS subscriptions (
    id        TEXT PRIMARY KEY,
    doctorId  TEXT NOT NULL,
    plan      TEXT,
    status    TEXT,
    startedAt INTEGER,
    renewsAt  INTEGER,
    FOREIGN KEY (doctorId) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS questionnaires (
    id          TEXT PRIMARY KEY,
    clientId    TEXT,
    doctorId    TEXT NOT NULL,
    submittedBy TEXT NOT NULL,
    stage       TEXT NOT NULL,
    orderNumber INTEGER NOT NULL,
    data        TEXT,
    doctorNote  TEXT,
    createdAt   INTEGER NOT NULL,
    FOREIGN KEY (clientId) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (doctorId) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_q_doctor ON questionnaires(doctorId);
  CREATE INDEX IF NOT EXISTS idx_q_client ON questionnaires(clientId);
`);

/* ---------- ids & passwords ---------- */

export const newId = (prefix = 'id') => `${prefix}_${randomUUID().replace(/-/g, '')}`;
export const newToken = () => randomBytes(32).toString('hex');

export function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const expected = Buffer.from(hash, 'hex');
  const actual = scryptSync(password, salt, 64);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/* ---------- seed demo accounts on first run ---------- */

function seed() {
  const count = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  if (count > 0) return;

  const now = Date.now();
  const insertUser = db.prepare(`
    INSERT INTO users (id, role, email, passwordHash, fullName, phone, clinic, specialization, city, status, createdAt)
    VALUES (@id, @role, @email, @passwordHash, @fullName, @phone, @clinic, @specialization, @city, @status, @createdAt)
  `);
  const insertSub = db.prepare(`
    INSERT INTO subscriptions (id, doctorId, plan, status, startedAt, renewsAt)
    VALUES (@id, @doctorId, @plan, @status, @startedAt, @renewsAt)
  `);

  insertUser.run({
    id: 'u_admin', role: 'admin', email: 'admin@tmj.local',
    passwordHash: hashPassword('admin1234'), fullName: 'System Admin',
    phone: null, clinic: null, specialization: null, city: null, status: null, createdAt: now,
  });
  insertUser.run({
    id: 'u_doctor', role: 'doctor', email: 'doctor@tmj.local',
    passwordHash: hashPassword('doctor1234'), fullName: 'Dr. Demo',
    phone: '+998 90 000 00 00', clinic: 'Demo Dental Clinic',
    specialization: 'orthodontist', city: 'Tashkent', status: 'active', createdAt: now,
  });
  // 'suspended' is the only state that hides a doctor from patients — doctors are
  // never gated on admin approval, so this row demos suspend/reactivate instead.
  insertUser.run({
    id: 'u_suspended', role: 'doctor', email: 'suspended@tmj.local',
    passwordHash: hashPassword('doctor1234'), fullName: 'Dr. Suspended',
    phone: '+998 90 111 11 11', clinic: 'Suspended Clinic',
    specialization: 'neurologist', city: 'Samarkand', status: 'suspended', createdAt: now,
  });

  insertSub.run({ id: newId('sub'), doctorId: 'u_doctor', plan: 'basic', status: 'active', startedAt: now, renewsAt: now + 30 * 86400e3 });
  insertSub.run({ id: newId('sub'), doctorId: 'u_suspended', plan: 'basic', status: 'suspended', startedAt: now, renewsAt: null });

  console.log('[db] seeded demo accounts (admin@tmj.local / doctor@tmj.local / suspended@tmj.local)');
}

/* ---------- migrations ---------- */

// Doctors used to sign up as 'pending' and stay invisible to patients until an
// admin approved them. That gate is gone: a doctor is live the moment they
// register. Release any doctor still stuck in the old state (idempotent — nothing
// writes 'pending' anymore, so this is a no-op on every boot after the first).
function releasePendingDoctors() {
  const stuck = db.prepare(
    "SELECT id FROM users WHERE role = 'doctor' AND (status IS NULL OR status = 'pending')",
  ).all();
  if (stuck.length === 0) return;

  const now = Date.now();
  const activateUser = db.prepare("UPDATE users SET status = 'active' WHERE id = ?");
  const activateSub = db.prepare(
    "UPDATE subscriptions SET status = 'active', startedAt = COALESCE(startedAt, ?), renewsAt = ? WHERE doctorId = ? AND (status IS NULL OR status = 'pending')",
  );
  for (const { id } of stuck) {
    activateUser.run(id);
    activateSub.run(now, now + 30 * 86400e3, id);
  }
  console.log(`[db] activated ${stuck.length} doctor(s) left over from the old approval flow`);
}

seed();
releasePendingDoctors();
