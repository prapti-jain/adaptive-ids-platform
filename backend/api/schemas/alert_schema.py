"""Pydantic schemas for alert API responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from backend.models.domain import Alert, AlertStatus, AttackType, EnrichedAlert, Severity


class AlertSchema(BaseModel):
    """API mirror of the domain ``Alert`` dataclass."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_name: str
    attack_type: AttackType
    source_ip: str
    target_ip: str | None
    severity: Severity
    confidence: float
    risk_score: float
    status: AlertStatus
    evidence: dict[str, Any]
    detected_at: datetime

    @classmethod
    def from_domain(cls, alert: Alert) -> AlertSchema:
        return cls(
            id=alert.id,
            rule_name=alert.rule_name,
            attack_type=alert.attack_type,
            source_ip=alert.source_ip,
            target_ip=alert.target_ip,
            severity=alert.severity,
            confidence=alert.confidence,
            risk_score=alert.risk_score,
            status=alert.status,
            evidence=dict(alert.evidence),
            detected_at=alert.detected_at,
        )


class EnrichedAlertSchema(BaseModel):
    """API mirror of the domain ``EnrichedAlert`` dataclass."""

    model_config = ConfigDict(from_attributes=True)

    alert: AlertSchema
    ip_reputation: str
    geo_country: str | None
    is_known_malicious: bool
    historical_alert_count: int

    @classmethod
    def from_domain(cls, enriched: EnrichedAlert) -> EnrichedAlertSchema:
        return cls(
            alert=AlertSchema.from_domain(enriched.alert),
            ip_reputation=enriched.ip_reputation,
            geo_country=enriched.geo_country,
            is_known_malicious=enriched.is_known_malicious,
            historical_alert_count=enriched.historical_alert_count,
        )


class AlertListResponse(BaseModel):
    items: list[EnrichedAlertSchema]
    total: int
    limit: int
    offset: int


class AlertStatusUpdate(BaseModel):
    status: Literal["INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]


class OverviewStats(BaseModel):
    window_hours: float
    total: int
    by_severity: dict[str, int]
    by_attack_type: dict[str, int]


class TimelineBucket(BaseModel):
    bucket: str
    count: int


class TimelineStats(BaseModel):
    interval: str
    buckets: list[TimelineBucket]


class TopAttacker(BaseModel):
    source_ip: str
    alert_count: int


class TopAttackersResponse(BaseModel):
    items: list[TopAttacker]


class TopPort(BaseModel):
    port: int
    alert_count: int


class TopPortsResponse(BaseModel):
    items: list[TopPort]
    note: str = Field(
        default=(
            "Counts are derived from alert evidence: evidence['target_port'] "
            "(SYN flood / SSH) and evidence['target_ports'] (port scan). "
            "target_port is not a first-class Alert column."
        )
    )


class PipelineReplayRequest(BaseModel):
    pcap_path: str | None = None


class PipelineReplayResponse(BaseModel):
    processed_events: int
    pcap_path: str
