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
- `CORS_ORIGIN` — comma-separated origins allowed to call the API with a session
  cookie, e.g. `https://abdurayim.github.io`. **Set this in production.** Unset
  means "reflect whatever origin asks", which is fine for local development but
  in production would let any site on the internet make authenticated calls with
  a logged-in user's session.

## Uploads and body size

A questionnaire carries the patient photo and any x-rays inline as base64, so a
saved record is a single large JSON body. The API accepts up to **25 MB**
(`express.json({ limit: '25mb' })`) and the web app downscales every image to
1600px before encoding, which keeps a typical record well under 1 MB.

If you put a reverse proxy in front of this, raise its body limit to match or
saving silently fails with a 413 — nginx defaults to **1 MB**, which is smaller
than a single phone photo:

```nginx
client_max_body_size 25m;
```

nginx must also forward the protocol, or the session cookie never gets its
`Secure` flag and browsers drop it on the cross-site request from the web app:

```nginx
proxy_set_header X-Forwarded-Proto $scheme;
```
