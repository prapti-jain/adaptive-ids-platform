"""AIDTIP FastAPI application."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routers import alerts, pipeline, reports, stats, ws
from backend.config.settings import settings

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
