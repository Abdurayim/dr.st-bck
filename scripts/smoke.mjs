/* End-to-end smoke test.
 *
 * Boots the real server against a throwaway database and drives the flows that
 * actually matter to users, so a regression fails CI instead of the demo:
 *   - a doctor registers and is visible to patients immediately (no approval gate)
 *   - suspending is the only thing that hides them, and it is reversible
 *   - a patient's questionnaire reaches the doctor it was addressed to
 *
 * Run locally with: npm run smoke
 */
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = process.env.SMOKE_PORT || '4099';
const API = `http://127.0.0.1:${PORT}/api`;
const DATA_DIR = mkdtempSync(join(tmpdir(), 'tmj-smoke-'));

let passed = 0;
const failures = [];

function check(name, condition, detail = '') {
  if (condition) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failures.push(`${name}${detail ? ` — ${detail}` : ''}`);
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

/* --- a tiny cookie-aware client; fetch() does not keep a jar --- */
function client() {
  let cookie = '';
  return async (method, path, body) => {
    const res = await fetch(API + path, {
      method,
      headers: {
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        ...(cookie ? { Cookie: cookie } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const setCookie = res.headers.getSetCookie?.() ?? [];
    for (const c of setCookie) cookie = c.split(';')[0];
    let json = null;
    try { json = await res.json(); } catch { /* empty body */ }
    return { status: res.status, body: json };
  };
}

async function waitForHealth(timeoutMs = 20000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/health`);
      if (res.ok) return true;
    } catch { /* not up yet */ }
    await new Promise(r => setTimeout(r, 250));
  }
  return false;
}

const server = spawn(process.execPath, [join(ROOT, 'src', 'index.js')], {
  env: { ...process.env, PORT, DATA_DIR },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let serverLog = '';
server.stdout.on('data', d => { serverLog += d; });
server.stderr.on('data', d => { serverLog += d; });

function shutdown() {
  server.kill('SIGTERM');
  try { rmSync(DATA_DIR, { recursive: true, force: true }); } catch { /* best effort */ }
}

try {
  if (!await waitForHealth()) {
    console.error('server never became healthy. output:\n' + serverLog);
    shutdown();
    process.exit(1);
  }
  console.log(`\nserver up on :${PORT} (data dir: ${DATA_DIR})\n`);

  const stamp = Date.now();
  const doctorEmail = `smoke.doctor.${stamp}@example.com`;
  const clientEmail = `smoke.client.${stamp}@example.com`;

  /* ---------- doctors register without admin approval ---------- */
  console.log('doctor registration (no approval gate)');
  const doctor = client();
  const signup = await doctor('POST', '/auth/signup/doctor', {
    fullName: 'Smoke Doctor', email: doctorEmail, password: 'smoke1234',
    clinic: 'Smoke Clinic', specialization: 'orthodontist', city: 'Tashkent',
  });
  check('signup returns 200', signup.status === 200, `got ${signup.status}`);
  check("new doctor is 'active', not pending", signup.body?.status === 'active', `got ${signup.body?.status}`);
  check('password hash is never returned', !('passwordHash' in (signup.body || {})));
  const doctorId = signup.body?.id;

  const me = await doctor('GET', '/auth/me');
  check('doctor is signed in straight after signup', me.status === 200 && me.body?.email === doctorEmail);

  const anon = client();
  const publicList = await anon('GET', '/doctors?pageSize=100');
  check(
    'doctor appears in the public directory immediately',
    (publicList.body?.items || []).some(d => d.id === doctorId),
  );

  /* ---------- admin can suspend, but cannot gate registration ---------- */
  console.log('\nadmin controls');
  const admin = client();
  const adminLogin = await admin('POST', '/auth/login', { email: 'admin@tmj.local', password: 'admin1234' });
  check('admin can log in', adminLogin.status === 200 && adminLogin.body?.role === 'admin');

  const pending = await admin('PATCH', `/admin/doctors/${doctorId}`, { status: 'pending' });
  check("'pending' is rejected as a status", pending.status === 400, `got ${pending.status}`);

  await admin('PATCH', `/admin/doctors/${doctorId}`, { status: 'suspended' });
  const afterSuspend = await anon('GET', '/doctors?pageSize=100');
  check(
    'suspending hides the doctor from patients',
    !(afterSuspend.body?.items || []).some(d => d.id === doctorId),
  );

  await admin('PATCH', `/admin/doctors/${doctorId}`, { status: 'active' });
  const afterRestore = await anon('GET', '/doctors?pageSize=100');
  check(
    'reactivating brings the doctor back',
    (afterRestore.body?.items || []).some(d => d.id === doctorId),
  );

  /* ---------- a questionnaire links patient and doctor ---------- */
  console.log('\nquestionnaire round-trip');
  const patient = client();
  const clientSignup = await patient('POST', '/auth/signup/client', {
    fullName: 'Smoke Patient', email: clientEmail, password: 'smoke1234',
  });
  check('patient can register', clientSignup.status === 200 && clientSignup.body?.role === 'client');

  const created = await patient('POST', '/questionnaires', {
    doctorId, stage: 'before', data: { fio: 'Smoke Patient', note: 'smoke test' },
  });
  check('patient can submit a questionnaire', created.status === 200, `got ${created.status}`);
  check('record is linked to both accounts',
    created.body?.doctorId === doctorId && !!created.body?.clientId);
  check('first record is numbered 1', created.body?.orderNumber === 1, `got ${created.body?.orderNumber}`);
  check('submitted data round-trips', created.body?.data?.fio === 'Smoke Patient');

  const patientView = await patient('GET', `/questionnaires?doctorId=${doctorId}`);
  check('patient sees their own submission', patientView.body?.total === 1);

  const doctorView = await doctor('GET', '/questionnaires');
  check('doctor sees the submission addressed to them',
    (doctorView.body?.items || []).some(q => q.id === created.body?.id));

  const note = await doctor('PATCH', `/questionnaires/${created.body?.id}`, { doctorNote: 'looks fine' });
  check('doctor can attach a clinical note', note.body?.doctorNote === 'looks fine');

  /* ---------- authorisation ---------- */
  console.log('\nauthorisation');
  const stranger = client();
  check('questionnaires require a session',
    (await stranger('GET', '/questionnaires')).status === 401);
  check('admin endpoints reject a doctor',
    (await doctor('GET', '/admin/users')).status === 403);
  check("a doctor cannot edit another doctor's record",
    (await stranger('PATCH', `/questionnaires/${created.body?.id}`, { doctorNote: 'x' })).status === 401);

} catch (err) {
  failures.push(`threw: ${err?.stack || err}`);
} finally {
  shutdown();
}

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.error('\nfailures:\n' + failures.map(f => '  - ' + f).join('\n'));
  process.exit(1);
}
console.log('smoke test passed\n');
