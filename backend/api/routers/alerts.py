"""Alert REST endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.alerts.mappers import alert_from_orm
from backend.api.schemas.alert_schema import (
    AlertListResponse,
    AlertStatusUpdate,
    EnrichedAlertSchema,
)
from backend.api.ws_manager import ws_manager
from backend.database.models import AlertORM
from backend.database.session import get_db
from backend.intelligence.enrichment_service import EnrichmentService
from backend.models.domain import AlertStatus

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _to_schema(session: Session, orm: AlertORM) -> EnrichedAlertSchema:
    alert = alert_from_orm(orm)
    enriched = EnrichmentService(session).attach_cached_enrichment(alert)
    return EnrichedAlertSchema.from_domain(enriched)


@router.get("", response_model=AlertListResponse)
def list_alerts(
    severity: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    attack_type: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> AlertListResponse:
    """Paginated alerts, newest first, with optional filters."""
    filters = []
    if severity is not None:
        filters.append(AlertORM.severity == severity)
    if status_filter is not None:
        filters.append(AlertORM.status == status_filter)
    if attack_type is not None:
        filters.append(AlertORM.attack_type == attack_type)

    total_stmt = select(func.count()).select_from(AlertORM)
    list_stmt = select(AlertORM)
    if filters:
        total_stmt = total_stmt.where(*filters)
        list_stmt = list_stmt.where(*filters)

    total = db.scalar(total_stmt) or 0

    stmt = (
        list_stmt.order_by(AlertORM.detected_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = db.scalars(stmt).all()
    items = [_to_schema(db, row) for row in rows]
    return AlertListResponse(items=items, total=int(total), limit=limit, offset=offset)


@router.get("/{alert_id}", response_model=EnrichedAlertSchema)
def get_alert(alert_id: UUID, db: Session = Depends(get_db)) -> EnrichedAlertSchema:
    """Return a single alert with cached enrichment attached."""
    orm = db.get(AlertORM, alert_id)
    if orm is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return _to_schema(db, orm)


@router.patch("/{alert_id}/status", response_model=EnrichedAlertSchema)
async def update_alert_status(
    alert_id: UUID,
    body: AlertStatusUpdate,
    db: Session = Depends(get_db),
) -> EnrichedAlertSchema:
    """Update alert workflow status and broadcast the change."""
    orm = db.get(AlertORM, alert_id)
    if orm is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    orm.status = AlertStatus(body.status).value
    db.add(orm)
    db.commit()
    db.refresh(orm)

    schema = _to_schema(db, orm)
    await ws_manager.broadcast(schema.model_dump(mode="json"))
    return schema
