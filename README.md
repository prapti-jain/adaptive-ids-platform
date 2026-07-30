# AIDTIP — Adaptive Intrusion Detection & Threat Intelligence Platform

AIDTIP is a modular platform for offline PCAP replay (and optional live capture), signature-style intrusion detection, alert scoring, threat-intel enrichment, REST/WebSocket APIs, a SOC-style React dashboard, and printable incident reports.

## Architecture

See **[docs/architecture.md](docs/architecture.md)** for the pipeline diagram and module map.

Short version: **capture → parse → detect → classify → persist alerts → enrich → API/dashboard → reports**.

## Local development (SQLite — the working path)

Docker is **not required**. On machines without Docker or with restricted outbound network access, use file-based SQLite.

```bash
cd adaptive-ids-platform
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # DATABASE_URL=sqlite:///./aidtip.db
alembic upgrade head

# optional: regenerate sample traffic with recent timestamps
python scripts/generate_sample_pcap.py
python scripts/run_pipeline.py
```

### API + dashboard

```bash
# terminal 1 — backend
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000

# terminal 2 — frontend (uses port 5174 to avoid clashes with other Vite apps)
cd frontend
npm install
npm run dev
```

- API health: http://127.0.0.1:8000/health  
- Dashboard: http://127.0.0.1:5174/  
- From the Overview tab, click **Replay Sample PCAP** to drive live WebSocket alerts.

### Reports

```bash
# create a report for a time range (ISO-8601), then download HTML
curl -X POST http://127.0.0.1:8000/api/reports \
  -H 'Content-Type: application/json' \
  -d '{"start":"2026-01-01T00:00:00Z","end":"2030-01-01T00:00:00Z"}'

curl -o report.html http://127.0.0.1:8000/api/reports/<id>/download
```

### Tests

```bash
pytest
```

## Docker / Postgres (documented production path)

`docker-compose.yml`, `backend/Dockerfile`, and `frontend/Dockerfile` describe a Postgres + API + Vite stack for environments **with Docker and network access**. They are **documented but unverified** on restricted office laptops without admin rights / Docker Desktop. Prefer the SQLite path above for local development and grading.

For **Render + Neon** cloud deploy steps, see **[docs/deployment.md](docs/deployment.md)**.

## Office-network note (optional)

This project was developed on a machine without Docker admin rights and with unreliable outbound access to managed Postgres. Local default is therefore SQLite; the ORM/migrations remain Postgres-compatible for later deployment.

## Honest scope / gaps vs. a full IDS architecture

Implemented:

- Offline PCAP generation/replay, packet parsing, **3** detection rules (port scan, SYN flood, SSH brute force)
- Scoring, alert dedup, SQLite/Postgres-compatible persistence, Alembic migrations
- Mock threat-intel enrichment, REST + WebSocket API, React SOC dashboard, HTML reports

Not implemented / simplified:

- **Detection rules:** ICMP flood, ARP spoofing, DNS spoofing (and other original multi-rule lists beyond the three above) were **not** built
- **`backend/response/`:** placeholder only — no automated response / recommendation advisor
- **Live capture:** implemented but requires privileges; PCAP replay is the primary path
- **Real threat-intel APIs:** mock provider only (`intelligence.provider: mock`)
- **Auth / multi-tenant / Redis pub-sub:** out of scope
- **Docker Compose:** present as docs/artifacts, not the verified local run path
- **Frontend port:** local Vite uses **5174** (not 5173) to avoid collisions with other projects on the same machine
