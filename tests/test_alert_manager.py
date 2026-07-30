"""Unit tests for AlertManager deduplication and persistence."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.alerts.alert_manager import AlertManager
from backend.database.base import Base
from backend.database.models import AlertORM
from backend.models.domain import DetectionEvent


@pytest.fixture()
def db_session() -> Session:
    """In-memory SQLite session with the alerts schema created."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def _config(cooldown_seconds: float = 60) -> dict:
    return {
        "classification": {
            "severity_bands": {
                "LOW": 0.25,
                "MEDIUM": 0.5,
                "HIGH": 0.75,
                "CRITICAL": 1.0,
            },
            "alert_cooldown_seconds": cooldown_seconds,
        }
    }


def _event(
    *,
    source_ip: str = "10.0.0.50",
    timestamp: datetime,
    attempts: int = 20,
) -> DetectionEvent:
    return DetectionEvent(
        rule_name="ssh_bruteforce",
        source_ip=source_ip,
        target_ip="10.0.0.22",
        evidence={"attempts": attempts, "threshold": 10, "target_port": 22},
        timestamp=timestamp,
    )


def test_alert_manager_deduplicates_within_cooldown(db_session: Session):
    manager = AlertManager(db_session, config=_config(cooldown_seconds=60))
    start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    first = manager.handle(_event(timestamp=start, attempts=15))
    second = manager.handle(
        _event(timestamp=start + timedelta(seconds=30), attempts=25)
    )

    assert first.id == second.id
    assert second.evidence["attempts"] == 25
    assert second.detected_at == start + timedelta(seconds=30)

    rows = db_session.scalars(select(AlertORM)).all()
    assert len(rows) == 1
    assert rows[0].id == first.id
    assert rows[0].evidence["attempts"] == 25


def test_alert_manager_creates_new_alert_after_cooldown(db_session: Session):
    manager = AlertManager(db_session, config=_config(cooldown_seconds=60))
    start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    first = manager.handle(_event(timestamp=start, attempts=15))
    later = manager.handle(
        _event(timestamp=start + timedelta(seconds=61), attempts=18)
    )

    assert first.id != later.id

    rows = db_session.scalars(select(AlertORM)).all()
    assert len(rows) == 2
    assert {row.id for row in rows} == {first.id, later.id}
