"""Statistics REST endpoints."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.schemas.alert_schema import (
    OverviewStats,
    TimelineBucket,
    TimelineStats,
    TopAttacker,
    TopAttackersResponse,
    TopPort,
    TopPortsResponse,
)
from backend.database.models import AlertORM
from backend.database.session import get_db

router = APIRouter(prefix="/api/stats", tags=["stats"])


def _cutoff(window_hours: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=window_hours)


@router.get("/overview", response_model=OverviewStats)
def overview(
    window_hours: float = Query(default=24.0, gt=0, le=24 * 30),
    db: Session = Depends(get_db),
) -> OverviewStats:
    """Alert counts by severity and attack_type over a sliding window."""
    cutoff = _cutoff(window_hours)
    rows = db.scalars(
        select(AlertORM).where(AlertORM.detected_at >= cutoff)
    ).all()

    by_severity: Counter[str] = Counter()
    by_attack_type: Counter[str] = Counter()
    for row in rows:
        by_severity[row.severity] += 1
        by_attack_type[row.attack_type] += 1

    return OverviewStats(
        window_hours=window_hours,
        total=len(rows),
        by_severity=dict(by_severity),
        by_attack_type=dict(by_attack_type),
    )


@router.get("/timeline", response_model=TimelineStats)
def timeline(
    interval: str = Query(default="hour", pattern="^(hour|day)$"),
    window_hours: float = Query(default=24.0, gt=0, le=24 * 90),
    db: Session = Depends(get_db),
) -> TimelineStats:
    """Alert counts bucketed by hour or day for charting."""
    cutoff = _cutoff(window_hours)
    rows = db.scalars(
        select(AlertORM)
        .where(AlertORM.detected_at >= cutoff)
        .order_by(AlertORM.detected_at.asc())
    ).all()

    buckets: Counter[str] = Counter()
    for row in rows:
        ts = row.detected_at
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if interval == "day":
            key = ts.strftime("%Y-%m-%d")
        else:
            key = ts.strftime("%Y-%m-%dT%H:00:00Z")
        buckets[key] += 1

    ordered = [
        TimelineBucket(bucket=key, count=count)
        for key, count in sorted(buckets.items())
    ]
    return TimelineStats(interval=interval, buckets=ordered)


@router.get("/top-attackers", response_model=TopAttackersResponse)
def top_attackers(
    limit: int = Query(default=10, ge=1, le=100),
    window_hours: float = Query(default=24.0 * 30, gt=0, le=24 * 365),
    db: Session = Depends(get_db),
) -> TopAttackersResponse:
    """Most frequent source_ip values by alert count."""
    cutoff = _cutoff(window_hours)
    stmt = (
        select(AlertORM.source_ip, func.count().label("alert_count"))
        .where(AlertORM.detected_at >= cutoff)
        .group_by(AlertORM.source_ip)
        .order_by(func.count().desc())
        .limit(limit)
    )
    rows = db.execute(stmt).all()
    return TopAttackersResponse(
        items=[TopAttacker(source_ip=ip, alert_count=int(count)) for ip, count in rows]
    )


@router.get("/top-ports", response_model=TopPortsResponse)
def top_ports(
    limit: int = Query(default=10, ge=1, le=100),
    window_hours: float = Query(default=24.0 * 30, gt=0, le=24 * 365 * 20),
    db: Session = Depends(get_db),
) -> TopPortsResponse:
    """Most targeted ports derived from alert evidence.

    Supports ``evidence.target_port`` (single port — SYN flood / SSH) and
    ``evidence.target_ports`` (list — port scan). Each distinct port on an
    alert is counted once toward that alert.
    """
    cutoff = _cutoff(window_hours)
    rows = db.scalars(
        select(AlertORM).where(AlertORM.detected_at >= cutoff)
    ).all()

    counts: Counter[int] = Counter()
    for row in rows:
        for port in _ports_from_evidence(row.evidence or {}):
            counts[port] += 1

    items = [
        TopPort(port=port, alert_count=count)
        for port, count in counts.most_common(limit)
    ]
    return TopPortsResponse(items=items)


def _ports_from_evidence(evidence: dict) -> set[int]:
    """Collect destination ports from ``target_port`` and/or ``target_ports``."""
    ports: set[int] = set()

    raw_list = evidence.get("target_ports")
    if isinstance(raw_list, list):
        for value in raw_list:
            try:
                ports.add(int(value))
            except (TypeError, ValueError):
                continue

    raw_single = evidence.get("target_port")
    if raw_single is not None:
        try:
            ports.add(int(raw_single))
        except (TypeError, ValueError):
            pass

    return ports
