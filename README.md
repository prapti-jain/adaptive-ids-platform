# AIDTIP

**Adaptive Intrusion Detection & Threat Intelligence Platform**

End-to-end intrusion detection demo: offline PCAP replay → signature detection → scored alerts → mock threat-intel enrichment → REST/WebSocket API → SOC dashboard → printable HTML reports.

Built as a modular Python + React system that runs locally on SQLite and deploys to Neon Postgres, Render, and Vercel.

---

## Live demo

| Surface | URL |
|---------|-----|
| **SOC dashboard** | [https://adaptive-ids-platform.vercel.app](https://adaptive-ids-platform.vercel.app) |
| **API** | [https://adaptive-backend-qmc1.onrender.com](https://adaptive-backend-qmc1.onrender.com) |
| **Health check** | [https://adaptive-backend-qmc1.onrender.com/health](https://adaptive-backend-qmc1.onrender.com/health) |
| **OpenAPI docs** | [https://adaptive-backend-qmc1.onrender.com/docs](https://adaptive-backend-qmc1.onrender.com/docs) |
| **Source** | [github.com/prapti-jain/adaptive-ids-platform](https://github.com/prapti-jain/adaptive-ids-platform) |

**Try it:** open the dashboard → **Overview** → **Replay Sample PCAP**. Alerts stream over WebSocket into Live Alerts / Timeline. Generate an HTML report from the Reports API or UI flow.

> Free-tier cold starts: the Render API may take ~30–60s to wake after idle. Refresh once if the first request times out.

---

## What it does

```
PCAP / live capture → parse → detect → classify & score → persist alerts
                         ↓
              mock threat intel enrich → REST + WebSocket → React SOC UI → HTML reports
```

| Capability | Details |
|------------|---------|
| Capture | Offline PCAP replay (primary); optional live sniff where privileges allow |
| Detection | Port scan, SYN flood, SSH brute force (`backend/config/rules.yaml`) |
| Alerts | Severity scoring, deduplication, SQLite/Postgres persistence |
| Intel | Mock IP reputation enrichment (pluggable provider interface) |
| API | FastAPI REST + live WebSocket alert feed |
| UI | Dark SOC dashboard — Overview, Live Alerts, Timeline, Top Stats, History |
| Reports | Time-range HTML incident reports via `/api/reports` |

Architecture notes: **[docs/architecture.md](docs/architecture.md)** · Deploy guide: **[docs/deployment.md](docs/deployment.md)**

---

## Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3, FastAPI, SQLAlchemy, Alembic, Scapy, Uvicorn |
| Frontend | React (Vite), Tailwind |
| Local DB | SQLite (`sqlite:///./aidtip.db`) |
| Production DB | Neon Postgres |
| Hosting | API on [Render](https://render.com) · UI on [Vercel](https://vercel.com) |

---

## Quick start (local)

Docker is **not** required. Local default is file-based SQLite.

```bash
git clone https://github.com/prapti-jain/adaptive-ids-platform.git
cd adaptive-ids-platform

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # DATABASE_URL=sqlite:///./aidtip.db
alembic upgrade head
python scripts/generate_sample_pcap.py
```

```bash
# terminal 1 — API
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000

# terminal 2 — dashboard (port 5174)
cd frontend && npm install && npm run dev
```

| Local | URL |
|-------|-----|
| API health | http://127.0.0.1:8000/health |
| Dashboard | http://127.0.0.1:5174/ |
| OpenAPI | http://127.0.0.1:8000/docs |

```bash
pytest
```

---

## Production deployment

| Service | Platform | Live URL |
|---------|----------|----------|
| Backend API + WebSocket | Render (Python web service) | https://adaptive-backend-qmc1.onrender.com |
| Frontend | Vercel (`frontend/` as root) | https://adaptive-ids-platform.vercel.app |
| Database | Neon Postgres | via `DATABASE_URL` on Render |

### Backend (Render)

- **Build:** `pip install -r requirements.txt`
- **Start:** `python scripts/generate_sample_pcap.py && alembic upgrade head && uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
- **Env:** `DATABASE_URL` (Neon, `sslmode=require`), `ALLOWED_ORIGINS` including the Vercel origin, `RULES_CONFIG_PATH=backend/config/rules.yaml`

### Frontend (Vercel)

Root Directory = `frontend`. Build-time env:

```bash
VITE_API_BASE_URL=https://adaptive-backend-qmc1.onrender.com
VITE_WS_BASE_URL=wss://adaptive-backend-qmc1.onrender.com
```

Full step-by-step: **[docs/deployment.md](docs/deployment.md)** · Blueprint: `render.yaml` · Process: `Procfile`

---

## Project layout

```
adaptive-ids-platform/
├── backend/           # FastAPI app, detection, alerts, intel, reports, pipeline
├── frontend/          # React SOC dashboard
├── alembic/           # DB migrations (SQLite + Postgres)
├── scripts/           # sample PCAP + offline pipeline runner
├── docs/              # architecture, deployment, sample PCAP notes
├── samples/           # generated sample.pcap (gitignored; created on start)
├── Procfile           # Render / Heroku-style web process
└── render.yaml        # Render Blueprint
```

---

## API highlights

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness |
| `GET` | `/api/alerts` | List / filter alerts |
| `GET` | `/api/stats` | Aggregate SOC stats |
| `POST` | `/api/pipeline/replay` | Replay sample PCAP |
| `WS` | `/ws/alerts` | Live alert stream |
| `POST` | `/api/reports` | Create HTML report for a time range |
| `GET` | `/api/reports/{id}/download` | Download report |

---

## Scope & honesty

**Implemented:** PCAP generate/replay, packet parse, 3 detection rules, scoring & dedup, SQLite/Postgres persistence, mock intel, REST + WebSocket, React dashboard, HTML reports, cloud deploy (Render + Neon + Vercel).

**Not built / simplified:** broader rule sets (ICMP/ARP/DNS spoofing, etc.), automated response (`backend/response/` placeholder), real threat-intel APIs, auth/multi-tenant/Redis, verified Docker Compose on restricted laptops (Compose files are documented artifacts; SQLite is the verified local path).

---

## License

Educational / portfolio project. Use and adapt freely with attribution appreciated.
