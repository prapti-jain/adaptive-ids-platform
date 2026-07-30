"""SQLAlchemy ORM models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, JSON, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.base import Base
from backend.models.domain import AlertStatus


class AlertORM(Base):
    """Persisted alert row matching the ``alerts`` table schema.

    Uses portable SQLAlchemy types (``Uuid``, ``JSON``) so the same model
    works on SQLite (local dev) and Postgres (production/demo). UUIDs are
    generated in Python via ``uuid.uuid4`` — never server-side.
    """

    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    rule_name: Mapped[str] = mapped_column(String(64), nullable=False)
    attack_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=AlertStatus.OPEN.value,
        server_default=AlertStatus.OPEN.value,
    )
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    def __repr__(self) -> str:
        return (
            f"<AlertORM id={self.id} rule={self.rule_name} "
            f"source={self.source_ip} severity={self.severity}>"
        )


class IpReputationORM(Base):
    """Cached IP reputation / geo data from threat-intel providers."""

    __tablename__ = "ip_reputation"

    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    reputation_score: Mapped[float] = mapped_column(Float, nullable=False)
    is_known_malicious: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="0",
    )
    geo_country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)

    def __repr__(self) -> str:
        return (
            f"<IpReputationORM ip={self.ip} score={self.reputation_score} "
            f"malicious={self.is_known_malicious} source={self.source}>"
        )


class ReportORM(Base):
    """Persisted incident / period report generated from alerts."""

    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    def __repr__(self) -> str:
        return f"<ReportORM id={self.id} generated_at={self.generated_at}>"
