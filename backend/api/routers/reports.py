"""Report REST endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.api.schemas.report_schema import ReportCreateRequest, ReportSummaryResponse
from backend.database.models import ReportORM
from backend.database.session import get_db
from backend.reports.html_renderer import render_report_html
from backend.reports.report_generator import ReportGenerator

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post("", response_model=ReportSummaryResponse, status_code=status.HTTP_201_CREATED)
def create_report(
    body: ReportCreateRequest,
    db: Session = Depends(get_db),
) -> ReportSummaryResponse:
    """Generate and persist a report for the given time range."""
    try:
        payload = ReportGenerator().generate(body.start, body.end, db)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return ReportSummaryResponse(
        id=UUID(payload["id"]),
        generated_at=payload["generated_at"],
        period_start=payload["period_start"],
        period_end=payload["period_end"],
        summary=payload["summary"],
        top_attackers=payload["top_attackers"],
        top_ports=payload["top_ports"],
        alert_ids=payload["alert_ids"],
    )


@router.get("/{report_id}", response_model=ReportSummaryResponse)
def get_report(report_id: UUID, db: Session = Depends(get_db)) -> ReportSummaryResponse:
    orm = db.get(ReportORM, report_id)
    if orm is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    payload = orm.payload or {}
    return ReportSummaryResponse(
        id=orm.id,
        generated_at=orm.generated_at,
        period_start=orm.period_start,
        period_end=orm.period_end,
        summary=payload.get("summary", {}),
        top_attackers=payload.get("top_attackers", []),
        top_ports=payload.get("top_ports", []),
        alert_ids=payload.get("alert_ids", []),
    )


@router.get("/{report_id}/download")
def download_report(report_id: UUID, db: Session = Depends(get_db)) -> Response:
    """Return a printable HTML incident summary for the report."""
    orm = db.get(ReportORM, report_id)
    if orm is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    html = render_report_html(orm.payload or {})
    return Response(
        content=html,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'inline; filename="aidtip-report-{report_id}.html"'
        },
    )
