"""WebSocket endpoints for live alert streaming."""

from __future__ import annotations

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.api.ws_manager import ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/alerts")
async def alerts_websocket(websocket: WebSocket) -> None:
    """Push each new/updated EnrichedAlert JSON payload to connected clients."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive; clients are not required to send.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception:
        logger.debug("WebSocket error", exc_info=True)
        await ws_manager.disconnect(websocket)
