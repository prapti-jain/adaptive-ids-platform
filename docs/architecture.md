# AIDTIP Architecture (as implemented)

AIDTIP is organized as a pipeline of small modules:

```text
PCAP / live capture
        │
        ▼
   PacketParser  →  PacketRecord
        │
        ▼
  DetectionEngine (FlowTracker + Rule strategies)
        │
        ▼
     Scorer  →  Alert
        │
        ▼
   AlertManager (dedupe + persist)
        │
        ▼
 EnrichmentService (mock threat intel + ip_reputation cache)
        │
        ▼
 FastAPI REST/WebSocket  ←→  React SOC dashboard
        │
        ▼
 ReportGenerator (period HTML/JSON reports)
```

## Modules

| Area | Path | Role |
|------|------|------|
| Capture | `backend/capture/` | `PcapReplaySource` (primary), `LiveCaptureSource` (bonus) |
| Parser | `backend/parser/` | Scapy → `PacketRecord` |
| Detection | `backend/detection/` | Sliding-window flow state + 3 rules |
| Classification | `backend/classification/` | Confidence / severity / risk score |
| Alerts | `backend/alerts/` | Dedup + SQLAlchemy persistence |
| Intelligence | `backend/intelligence/` | Offline mock provider + enrichment |
| API | `backend/api/` | REST + WebSocket |
| Reports | `backend/reports/` | Period summaries + HTML download |
| Frontend | `frontend/` | Dark SOC dashboard (Vite + React + Tailwind) |

## Data stores

- **Local default:** SQLite (`sqlite:///./aidtip.db`)
- **Documented production:** Postgres via `docker-compose.yml` (not required for local grading)

Schema is managed with Alembic (`alerts`, `ip_reputation`, `reports`).

See also `docs/sample_pcap.md` for generating offline captures.
