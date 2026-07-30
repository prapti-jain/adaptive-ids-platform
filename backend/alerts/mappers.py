"""Convert between domain Alert and AlertORM."""

from __future__ import annotations

from datetime import datetime, timezone

from backend.database.models import AlertORM
from backend.models.domain import Alert, AlertStatus, AttackType, Severity


def _ensure_utc(value: datetime) -> datetime:
    """Normalize DB datetimes to timezone-aware UTC (SQLite returns naive)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def alert_to_orm(alert: Alert) -> AlertORM:
    """Map a domain ``Alert`` to a new ORM instance."""
    return AlertORM(
        id=alert.id,
        rule_name=alert.rule_name,
        attack_type=alert.attack_type.value,
        source_ip=alert.source_ip,
        target_ip=alert.target_ip,
        severity=alert.severity.value,
        confidence=alert.confidence,
        risk_score=alert.risk_score,
        status=alert.status.value,
        evidence=dict(alert.evidence),
        detected_at=alert.detected_at,
    )


def alert_from_orm(orm: AlertORM) -> Alert:
    """Map an ORM row to a domain ``Alert``."""
    return Alert(
        id=orm.id,
        rule_name=orm.rule_name,
        attack_type=AttackType(orm.attack_type),
        source_ip=orm.source_ip,
        target_ip=orm.target_ip,
        severity=Severity(orm.severity),
        confidence=orm.confidence,
        risk_score=orm.risk_score,
        status=AlertStatus(orm.status),
        evidence=dict(orm.evidence or {}),
        detected_at=_ensure_utc(orm.detected_at),
    )


def apply_alert_to_orm(orm: AlertORM, alert: Alert) -> None:
    """Copy mutable fields from ``alert`` onto an existing ORM row."""
    orm.rule_name = alert.rule_name
    orm.attack_type = alert.attack_type.value
    orm.source_ip = alert.source_ip
    orm.target_ip = alert.target_ip
    orm.severity = alert.severity.value
    orm.confidence = alert.confidence
    orm.risk_score = alert.risk_score
    orm.status = alert.status.value
    orm.evidence = dict(alert.evidence)
    orm.detected_at = alert.detected_at
