"""Shared PCAP replay pipeline used by CLI scripts and the API."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from sqlalchemy.orm import Session

from backend.alerts.alert_manager import AlertManager
from backend.capture.pcap_replay import PcapReplaySource
from backend.config.settings import settings
from backend.detection.engine import DetectionEngine
from backend.intelligence.enrichment_service import EnrichmentService
from backend.models.domain import EnrichedAlert
from backend.parser.packet_parser import PacketParser

OnEnriched = Callable[[EnrichedAlert], None]


def run_pcap_pipeline(
    session: Session,
    pcap_path: str | Path | None = None,
    *,
    on_enriched: OnEnriched | None = None,
) -> int:
    """Replay a PCAP through detection → alerts → enrichment.

    Args:
        session: SQLAlchemy session for persistence.
        pcap_path: Capture file path (defaults to ``settings.PCAP_PATH``).
        on_enriched: Optional callback invoked for each ``EnrichedAlert``
            (used to broadcast over WebSockets when the API is running).

    Returns:
        Number of detection events handled (alerts created or updated).
    """
    path = Path(pcap_path or settings.PCAP_PATH)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    detection = DetectionEngine()
    manager = AlertManager(session)
    enricher = EnrichmentService(session)
    handled = 0

    for raw in PcapReplaySource(path).capture():
        record = PacketParser.parse(raw)
        if record is None:
            continue
        for event in detection.process(record):
            alert = manager.handle(event)
            enriched = enricher.enrich(alert)
            handled += 1
            if on_enriched is not None:
                on_enriched(enriched)

    return handled
