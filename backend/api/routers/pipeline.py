"""API endpoints for triggering the detection pipeline (demo)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import APIRouter, HTTPException, status

from backend.api.schemas.alert_schema import (
    EnrichedAlertSchema,
    PipelineReplayRequest,
    PipelineReplayResponse,
)
from backend.api.ws_manager import ws_manager
from backend.config.settings import settings
from backend.database.session import SessionLocal
from backend.pipeline.runner import run_pcap_pipeline

router = APIRouter(prefix="/api/pipeline", tags=["pipeline"])


@router.post("/replay", response_model=PipelineReplayResponse)
async def replay_pcap(
    body: PipelineReplayRequest | None = None,
) -> PipelineReplayResponse:
    """Replay a PCAP through the full pipeline and broadcast enriched alerts.

    Each created/updated ``EnrichedAlert`` is pushed to ``/ws/alerts`` clients.
    Uses a dedicated DB session in a worker thread so SQLAlchemy sessions are
    not shared across threads.
    """
    path = Path((body.pcap_path if body and body.pcap_path else None) or settings.PCAP_PATH)
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"PCAP file not found: {path}",
        )

    loop = asyncio.get_running_loop()

    def job() -> int:
        db = SessionLocal()
        try:

            def on_enriched(enriched) -> None:
                payload = EnrichedAlertSchema.from_domain(enriched).model_dump(mode="json")
                future = asyncio.run_coroutine_threadsafe(
                    ws_manager.broadcast(payload),
                    loop,
                )
                try:
                    future.result(timeout=5)
                except Exception:
                    pass

            return run_pcap_pipeline(db, path, on_enriched=on_enriched)
        finally:
            db.close()

    try:
        processed = await asyncio.to_thread(job)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return PipelineReplayResponse(processed_events=processed, pcap_path=str(path))
