import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import {
  db, newId, newToken, hashPassword, verifyPassword,
} from './db.js';

const PORT = Number(process.env.PORT || 4000);
const SESSION_COOKIE = 'tmj_sid';
const DAY = 86400 * 1000;
const COOKIE_MAX_AGE = 30 * DAY;        // patients / admin
// doctors are the primary daily users — keep them signed in long-term.
// 400 days is the max persistent-cookie lifetime browsers honour (Chrome cap),
// and it is refreshed (sliding) on every app load, so active doctors effectively
// never get logged out.
const COOKIE_MAX_AGE_DOCTOR = 400 * DAY;

const cookieMaxAge = (role) => (role === 'doctor' ? COOKIE_MAX_AGE_DOCTOR : COOKIE_MAX_AGE);

const app = express();
// medical records embed base64 photos + pain-diagram data, so the default
// 100kb body limit is far too small — allow generous payloads
app.use(express.json({ limit: '25mb' }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true })); // reflects request origin, allows cookies

/* ---------- helpers ---------- */

class HttpError extends Error {
  constructor(status, message, code = null, details = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const lc = (s) => (s || '').toString().toLowerCase();

function sanitizeUser(u) {
  if (!u) return null;
  const { passwordHash, ...safe } = u;
  return safe;
}

function serializeQ(row) {
  if (!row) return null;
  return { ...row, data: row.data ? JSON.parse(row.data) : null };
}

function paginate(items, { page = 1, pageSize = 10 } = {}) {
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const current = Math.min(Math.max(1, +page || 1), totalPages);
  const slice = items.slice((current - 1) * pageSize, current * pageSize);
  return { items: slice, page: current, pageSize: +pageSize || 10, total, totalPages };
}

function currentUser(req) {
  const token = req.cookies?.[SESSION_COOKIE];
  if (!token) return null;
  const row = db.prepare('SELECT userId FROM sessions WHERE token = ?').get(token);
  if (!row) return null;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(row.userId) || null;
}

function requireUser(req, roles) {
  const u = currentUser(req);
  if (!u) throw new HttpError(401, 'unauthorized', 'unauthorized');
  if (roles && !roles.includes(u.role)) throw new HttpError(403, 'forbidden', 'forbidden');
  return u;
}

function setSession(res, userId, role) {
  const token = newToken();
  db.prepare('INSERT INTO sessions (token, userId, createdAt) VALUES (?, ?, ?)').run(token, userId, Date.now());
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // localhost over http
    maxAge: cookieMaxAge(role),
    path: '/',
  });
}

// re-issue the existing session cookie with a fresh max-age (sliding expiration)
function refreshSession(req, res, role) {
  const token = req.cookies?.[SESSION_COOKIE];
  if (!token) return;
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: cookieMaxAge(role),
    path: '/',
  });
}

function clearSession(req, res) {
  const token = req.cookies?.[SESSION_COOKIE];
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.clearCookie(SESSION_COOKIE, { path: '/' });
}

// wrap async handlers so thrown HttpErrors become JSON responses
const h = (fn) => (req, res) => {
  try {
    fn(req, res);
  } catch (e) {
    if (e instanceof HttpError) {
      res.status(e.status).json({ message: e.message, code: e.code, details: e.details });
    } else {
      console.error(e);
      res.status(500).json({ message: 'serverError', code: 'server_error' });
    }
  }
};

const router = express.Router();

/* ---------- auth ---------- */

router.post('/auth/login', h((req, res) => {
  const email = lc(req.body?.email);
  const password = req.body?.password || '';
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    throw new HttpError(401, 'invalidCredentials', 'invalid_credentials');
  }
  setSession(res, user.id, user.role);
  res.json(sanitizeUser(user));
}));

router.post('/auth/logout', h((req, res) => {
  clearSession(req, res);
  res.json({ ok: true });
}));

router.get('/auth/me', h((req, res) => {
  const u = currentUser(req);
  if (!u) throw new HttpError(401, 'unauthorized', 'unauthorized');
  refreshSession(req, res, u.role); // sliding expiration — extend on every app load
  res.json(sanitizeUser(u));
}));

router.post('/auth/signup/client', h((req, res) => {
  const { fullName, email, phone, password } = req.body || {};
  if (!email || !password) throw new HttpError(400, 'missingFields', 'missing_fields');
  const exists = db.prepare('SELECT 1 FROM users WHERE email = ?').get(lc(email));
  if (exists) throw new HttpError(409, 'emailTaken', 'email_taken');

  const user = {
    id: newId('u'), role: 'client', email: lc(email),
    passwordHash: hashPassword(password), fullName: fullName || null,
    phone: phone || null, clinic: null, specialization: null, city: null,
    status: null, createdAt: Date.now(),
  };
  db.prepare(`
    INSERT INTO users (id, role, email, passwordHash, fullName, phone, clinic, specialization, city, status, createdAt)
    VALUES (@id, @role, @email, @passwordHash, @fullName, @phone, @clinic, @specialization, @city, @status, @createdAt)
  `).run(user);
  setSession(res, user.id, user.role);
  res.json(sanitizeUser(user));
}));

router.post('/auth/signup/doctor', h((req, res) => {
  const { fullName, email, phone, password, clinic, specialization, city } = req.body || {};
  if (!email || !password) throw new HttpError(400, 'missingFields', 'missing_fields');
  const exists = db.prepare('SELECT 1 FROM users WHERE email = ?').get(lc(email));
  if (exists) throw new HttpError(409, 'emailTaken', 'email_taken');

  const now = Date.now();
  const user = {
    id: newId('u'), role: 'doctor', email: lc(email),
    passwordHash: hashPassword(password), fullName: fullName || null,
    phone: phone || null, clinic: clinic || null, specialization: specialization || null,
    city: city || null, status: 'active', createdAt: now,
  };
  db.prepare(`
    INSERT INTO users (id, role, email, passwordHash, fullName, phone, clinic, specialization, city, status, createdAt)
    VALUES (@id, @role, @email, @passwordHash, @fullName, @phone, @clinic, @specialization, @city, @status, @createdAt)
  `).run(user);
  db.prepare(`
    INSERT INTO subscriptions (id, doctorId, plan, status, startedAt, renewsAt)
    VALUES (?, ?, 'basic', 'active', ?, ?)
  `).run(newId('sub'), user.id, now, now + 30 * 86400e3);
  // doctors are active immediately and logged in right away
  setSession(res, user.id, user.role);
  res.json(sanitizeUser(user));
}));

/* ---------- doctors (public, active only) ---------- */

router.get('/doctors', h((req, res) => {
  const q = lc(req.query.q).trim();
  let rows = db.prepare("SELECT * FROM users WHERE role = 'doctor' AND status = 'active' ORDER BY createdAt").all();
  if (q) {
    rows = rows.filter((u) =>
      lc(u.fullName).includes(q) || lc(u.clinic).includes(q) || lc(u.city).includes(q));
  }
  const out = paginate(rows, { page: req.query.page ?? 1, pageSize: req.query.pageSize ?? 10 });
  res.json({ ...out, items: out.items.map(sanitizeUser) });
}));

router.get('/doctors/:id', h((req, res) => {
  const d = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'doctor' AND status = 'active'").get(req.params.id);
  if (!d) throw new HttpError(404, 'notFound', 'not_found');
  res.json(sanitizeUser(d));
}));

/* ---------- questionnaires ---------- */

router.get('/questionnaires', h((req, res) => {
  const user = requireUser(req, ['client', 'doctor']);
  let rows;
  if (user.role === 'client') {
    if (req.query.doctorId) {
      rows = db.prepare('SELECT * FROM questionnaires WHERE clientId = ? AND doctorId = ?').all(user.id, req.query.doctorId);
    } else {
      rows = db.prepare('SELECT * FROM questionnaires WHERE clientId = ?').all(user.id);
    }
  } else {
    rows = db.prepare('SELECT * FROM questionnaires WHERE doctorId = ?').all(user.id);
  }
  rows.sort((a, b) => a.orderNumber - b.orderNumber);
  res.json({ items: rows.map(serializeQ), total: rows.length });
}));

router.post('/questionnaires', h((req, res) => {
  const user = requireUser(req, ['client', 'doctor']);
  const { stage, data = null, doctorId: bodyDoctorId } = req.body || {};
  if (stage !== 'before' && stage !== 'after') {
    throw new HttpError(400, 'invalidStage', 'invalid_stage');
  }

  let doctorId, clientId;
  if (user.role === 'client') {
    if (!bodyDoctorId) throw new HttpError(400, 'missingDoctor', 'missing_doctor');
    const doctor = db.prepare("SELECT id FROM users WHERE id = ? AND role = 'doctor' AND status = 'active'").get(bodyDoctorId);
    if (!doctor) throw new HttpError(404, 'notFound', 'not_found');
    doctorId = bodyDoctorId;
    clientId = user.id;
  } else {
    doctorId = user.id;
    clientId = null;
  }

  // order number is per (doctor, client) thread — record is linked to both accounts
  const prior = clientId
    ? db.prepare('SELECT COUNT(*) AS n FROM questionnaires WHERE doctorId = ? AND clientId = ?').get(doctorId, clientId).n
    : db.prepare('SELECT COUNT(*) AS n FROM questionnaires WHERE doctorId = ? AND clientId IS NULL').get(doctorId).n;

  const rec = {
    id: newId('q'),
    clientId,
    doctorId,
    submittedBy: user.role,
    stage,
    orderNumber: prior + 1,
    data: data == null ? null : JSON.stringify(data),
    doctorNote: null,
    createdAt: Date.now(),
  };
  db.prepare(`
    INSERT INTO questionnaires (id, clientId, doctorId, submittedBy, stage, orderNumber, data, doctorNote, createdAt)
    VALUES (@id, @clientId, @doctorId, @submittedBy, @stage, @orderNumber, @data, @doctorNote, @createdAt)
  `).run(rec);
  res.json(serializeQ(rec));
}));

router.patch('/questionnaires/:id', h((req, res) => {
  const user = requireUser(req, ['doctor']);
  const row = db.prepare('SELECT * FROM questionnaires WHERE id = ?').get(req.params.id);
  if (!row) throw new HttpError(404, 'notFound', 'not_found');
  if (row.doctorId !== user.id) throw new HttpError(403, 'forbidden', 'forbidden');
  if (typeof req.body?.doctorNote !== 'undefined') {
    const note = req.body.doctorNote || null;
    db.prepare('UPDATE questionnaires SET doctorNote = ? WHERE id = ?').run(note, row.id);
    row.doctorNote = note;
  }
  // doctors may edit the full record contents after creation
  if (typeof req.body?.data !== 'undefined') {
    const data = req.body.data == null ? null : JSON.stringify(req.body.data);
    db.prepare('UPDATE questionnaires SET data = ? WHERE id = ?').run(data, row.id);
    row.data = data;
  }
  res.json(serializeQ(row));
}));

/* ---------- admin ---------- */

router.get('/admin/users', h((req, res) => {
  requireUser(req, ['admin']);
  const q = lc(req.query.q).trim();
  const role = req.query.role || '';
  let rows = db.prepare('SELECT * FROM users ORDER BY createdAt').all();
  if (role) rows = rows.filter((u) => u.role === role);
  if (q) rows = rows.filter((u) => lc(u.fullName).includes(q) || lc(u.email).includes(q));
  const out = paginate(rows, { page: req.query.page ?? 1, pageSize: req.query.pageSize ?? 10 });
  res.json({ ...out, items: out.items.map(sanitizeUser) });
}));

router.get('/admin/doctors', h((req, res) => {
  requireUser(req, ['admin']);
  const q = lc(req.query.q).trim();
  const status = req.query.status || '';
  let rows = db.prepare("SELECT * FROM users WHERE role = 'doctor' ORDER BY createdAt").all();
  if (status) rows = rows.filter((u) => u.status === status);
  if (q) rows = rows.filter((u) =>
    lc(u.fullName).includes(q) || lc(u.email).includes(q) || lc(u.clinic).includes(q));
  const out = paginate(rows, { page: req.query.page ?? 1, pageSize: req.query.pageSize ?? 10 });
  res.json({ ...out, items: out.items.map(sanitizeUser) });
}));

router.patch('/admin/doctors/:id', h((req, res) => {
  requireUser(req, ['admin']);
  const status = req.body?.status;
  const doctor = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'doctor'").get(req.params.id);
  if (!doctor) throw new HttpError(404, 'notFound', 'not_found');
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, doctor.id);
  doctor.status = status;

  const sub = db.prepare('SELECT * FROM subscriptions WHERE doctorId = ?').get(doctor.id);
  if (sub) {
    if (status === 'active') {
      db.prepare('UPDATE subscriptions SET status = ?, startedAt = ?, renewsAt = ? WHERE id = ?')
        .run('active', sub.startedAt || Date.now(), Date.now() + 30 * 86400e3, sub.id);
    } else if (status === 'suspended') {
      db.prepare('UPDATE subscriptions SET status = ? WHERE id = ?').run('suspended', sub.id);
    } else if (status === 'pending') {
      db.prepare('UPDATE subscriptions SET status = ? WHERE id = ?').run('pending', sub.id);
    }
  }
  res.json(sanitizeUser(doctor));
}));

router.get('/admin/subscriptions', h((req, res) => {
  requireUser(req, ['admin']);
  const q = lc(req.query.q).trim();
  const status = req.query.status || '';
  let subs = db.prepare('SELECT * FROM subscriptions').all();
  if (status) subs = subs.filter((s) => s.status === status);
  let rows = subs.map((s) => {
    const doc = db.prepare('SELECT * FROM users WHERE id = ?').get(s.doctorId);
    return { ...s, doctor: doc ? sanitizeUser(doc) : null };
  });
  if (q) rows = rows.filter((r) => lc(r.doctor?.fullName).includes(q));
  res.json(paginate(rows, { page: req.query.page ?? 1, pageSize: req.query.pageSize ?? 10 }));
}));

app.use('/api', router);

app.get('/health', (_req, res) => res.json({ ok: true }));
app.use((_req, res) => res.status(404).json({ message: 'notFound', code: 'not_found' }));

app.listen(PORT, () => {
  console.log(`[server] TMJ API listening on http://localhost:${PORT}/api`);
});
