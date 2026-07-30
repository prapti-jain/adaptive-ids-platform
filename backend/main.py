"""AIDTIP FastAPI application."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routers import alerts, pipeline, reports, stats, ws

app = FastAPI(
    title="AIDTIP",
    description="Adaptive Intrusion Detection & Threat Intelligence Platform",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
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
