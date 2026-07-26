# TMJ Anketa — Backend

Real REST + SQLite backend for the questionnaire app. Replaces the old in-memory
localStorage mock so accounts and medical records actually persist.

- **DB:** SQLite via Node's built-in `node:sqlite` (file at `server/data/app.db`). No native build step.
- **Auth:** httpOnly cookie sessions; passwords hashed with `scrypt` (built-in `node:crypto`).
- **Deps:** only `express`, `cors`, `cookie-parser` (all pure JS).

## Run

```bash
# 1. backend (this folder)
cd server
npm install        # first time only
npm run dev        # or: npm start   → http://localhost:4000/api

# 2. frontend (repo root, separate terminal)
cd ..
npm run dev        # Vite → http://localhost:5173
```

The frontend talks to the API because `.env.local` has `VITE_USE_MOCK=0` and
`VITE_API_URL=http://localhost:4000/api`. Set `VITE_USE_MOCK=1` to fall back to the mock.

## Seeded demo accounts (created on first run only)

| Role   | Email               | Password   | Notes              |
|--------|---------------------|------------|--------------------|
| admin  | admin@tmj.local     | admin1234  |                    |
| doctor | doctor@tmj.local    | doctor1234 |                    |
| doctor | suspended@tmj.local | doctor1234 | status: `suspended` |

## Doctor visibility

Doctor registration needs **no admin approval**. `POST /auth/signup/doctor` creates the
account with `status: 'active'` and an active subscription, so the doctor shows up in the
public `GET /doctors` list — the one patients pick from — immediately after signing up.

An admin can only `suspend` a doctor (and lift it again) via `PATCH /admin/doctors/:id`;
`suspended` is the sole status that hides a doctor from patients. The old `pending` status
is rejected, and any doctor left on `pending` by an earlier version is migrated to `active`
on startup.

## Data model

A questionnaire row carries both `clientId` and `doctorId`, so each record is
**linked to both the patient's and the doctor's account** — patients see their own
submissions (and the doctor's notes); doctors see every record addressed to them.

## Reset

Delete `server/data/` to wipe all data and re-seed on next start.

## Config (env)

- `PORT` — API port (default `4000`)
- `DATA_DIR` — where `app.db` lives (default `server/data`)
