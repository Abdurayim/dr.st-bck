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
  insertUser.run({
    id: 'u_pending', role: 'doctor', email: 'pending@tmj.local',
    passwordHash: hashPassword('doctor1234'), fullName: 'Dr. Pending',
    phone: '+998 90 111 11 11', clinic: 'Pending Clinic',
    specialization: 'neurologist', city: 'Samarkand', status: 'pending', createdAt: now,
  });

  insertSub.run({ id: newId('sub'), doctorId: 'u_doctor', plan: 'basic', status: 'active', startedAt: now, renewsAt: now + 30 * 86400e3 });
  insertSub.run({ id: newId('sub'), doctorId: 'u_pending', plan: 'basic', status: 'pending', startedAt: null, renewsAt: null });

  console.log('[db] seeded demo accounts (admin@tmj.local / doctor@tmj.local / pending@tmj.local)');
}

seed();
