# Deploying AIDTIP backend (Render + Neon)

Local development continues to use SQLite via `.env`
(`DATABASE_URL=sqlite:///./aidtip.db`). Production must use a durable
Postgres database (e.g. Neon) because Render’s filesystem is ephemeral.

## Prerequisites

1. A Neon (or other) Postgres database and connection string with `sslmode=require`.
2. A Render account.
3. This repository pushed to GitHub/GitLab (Render connects to the git remote).

## Required environment variables

| Variable | Example / notes |
|----------|-----------------|
| `DATABASE_URL` | Neon URL, e.g. `postgresql://user:pass@host/db?sslmode=require` (**required** — no SQLite fallback in code) |
| `ALLOWED_ORIGINS` | Comma-separated frontend origins, e.g. `https://your-app.vercel.app,http://localhost:5174` |
| `RULES_CONFIG_PATH` | `backend/config/rules.yaml` |
| `LOG_LEVEL` | `INFO` |

Optional: `PCAP_PATH`, `CAPTURE_INTERFACE` (not needed for API-only deploy).

## Manual Render setup

1. **New → Web Service** → connect this repo.
2. **Runtime:** Python.
3. **Build command:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Start command:**
   ```bash
   uvicorn backend.main:app --host 0.0.0.0 --port $PORT
   ```
   (`$PORT` is injected by Render — do not hardcode `8000`.)
5. Add the env vars from the table above.
6. **Release / one-off migrate** (Shell or release command):
   ```bash
   alembic upgrade head
   ```
7. Deploy. Health check: `GET /health` → `{"status":"ok"}`.

Alternatively, use the repo’s `render.yaml` / `Procfile` if you prefer Blueprint or Heroku-style process definitions.

## Alembic note

`alembic/env.py` sets `sqlalchemy.url` from `settings.DATABASE_URL` with no
hostname assumptions. The same migrations run against SQLite locally and
Postgres/Neon in production (`render_as_batch` is enabled only for SQLite).

## Local vs production

| | Local | Production (Render) |
|--|-------|---------------------|
| DB | SQLite via `.env` | Neon Postgres via `DATABASE_URL` |
| Start | `uvicorn backend.main:app --reload --port 8000` | Procfile / start command with `$PORT` |
| CORS | defaults to localhost:5173/5174 | set `ALLOWED_ORIGINS` to Vercel (etc.) |

## Frontend (Vercel)

Deploy `frontend/` separately. Set Vite proxy is for local only — in
production point the API client at the Render URL (or configure a rewrite).
After the Vercel URL exists, append it to `ALLOWED_ORIGINS` on Render and
redeploy the backend (no code change required).
