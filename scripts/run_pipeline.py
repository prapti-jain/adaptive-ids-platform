#!/usr/bin/env python3
"""Replay samples/sample.pcap through parser → engine → alert_manager → enrichment.

Persists alerts / IP reputation to whatever DATABASE_URL is configured in .env.
When the API server is running in the same process this is not automatic —
use POST /api/pipeline/replay for WebSocket broadcasts. This CLI script still
accepts an optional --broadcast flag that is a no-op unless AIDTIP_WS_LOOP is
set; prefer the API endpoint for live demos.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.api.schemas.alert_schema import EnrichedAlertSchema
from backend.config.settings import settings
from backend.database.session import SessionLocal
from backend.pipeline.runner import run_pcap_pipeline


def main() -> int:
    pcap_path = Path(settings.PCAP_PATH)
    if not pcap_path.is_file():
        print(f"PCAP not found: {pcap_path}")
        print("Generate it with: .venv/bin/python scripts/generate_sample_pcap.py")
        return 1

    db = SessionLocal()
    created = 0

    def on_enriched(enriched) -> None:
        nonlocal created
        created += 1
        alert = enriched.alert
        print(
            f"id={alert.id} attack_type={alert.attack_type.value} "
            f"severity={alert.severity.value} risk_score={alert.risk_score:.4f} "
            f"source={alert.source_ip} "
            f"reputation={enriched.ip_reputation} "
            f"geo={enriched.geo_country} "
            f"malicious={enriched.is_known_malicious} "
            f"historical={enriched.historical_alert_count}"
        )
        # Best-effort broadcast if an event loop is already running (e.g. embedded).
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        payload = EnrichedAlertSchema.from_domain(enriched).model_dump(mode="json")
        from backend.api.ws_manager import ws_manager

        asyncio.run_coroutine_threadsafe(ws_manager.broadcast(payload), loop)

    try:
        run_pcap_pipeline(db, pcap_path, on_enriched=on_enriched)
    finally:
        db.close()

    print(f"Done. Alerts handled (new or updated): {created}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
