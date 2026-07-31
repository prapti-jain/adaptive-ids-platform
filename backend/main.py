"""AIDTIP FastAPI application."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routers import alerts, pipeline, reports, stats, ws
from backend.config.settings import settings
from backend.database.session import engine

logger = logging.getLogger("aidtip")
logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

# Redacted startup diagnostic — confirms which DB production is actually using.
_db_url = engine.url
logger.info(
    "Database configured: dialect=%s host=%s database=%s",
    engine.dialect.name,
    _db_url.host or "(none/local-file)",
    _db_url.database,
)
# Also print so it always appears in Render logs even if logging config differs.
print(
    f"[aidtip] Connected to DB dialect={engine.dialect.name}, "
    f"host={_db_url.host or '(none/local-file)'}, "
    f"database={_db_url.database}",
    flush=True,
)

app = FastAPI(
    title="AIDTIP",
    description="Adaptive Intrusion Detection & Threat Intelligence Platform",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router)
app.include_router(stats.router)
app.include_router(pipeline.router)
app.include_router(reports.router)
app.include_router(ws.router)


@app.get("/health")
def health():
    return {"status": "ok"}
