"""Unit tests for threat-intelligence enrichment."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.alerts.alert_manager import AlertManager
from backend.database.base import Base
from backend.database.models import IpReputationORM
from backend.intelligence.enrichment_service import EnrichmentService
from backend.intelligence.mock_provider import KNOWN_MALICIOUS_IPS, MockThreatIntelProvider
from backend.models.domain import DetectionEvent


@pytest.fixture()
def db_session() -> Session:
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
        },
        "intelligence": {"provider": "mock"},
    }


def _event(
    *,
    source_ip: str,
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


def test_mock_provider_is_deterministic():
    provider = MockThreatIntelProvider()
    ip = "203.0.113.10"
    first = provider.lookup(ip)
    second = provider.lookup(ip)
    assert first == second
    assert first.source == "mock"
    assert 0.0 <= first.reputation_score < 1.0 or first.is_known_malicious


def test_mock_provider_flags_known_malicious_ips():
    provider = MockThreatIntelProvider()
    for ip in KNOWN_MALICIOUS_IPS:
        result = provider.lookup(ip)
        assert result.is_known_malicious is True
        assert result.reputation_score >= 0.9


def test_enrichment_upserts_ip_reputation(db_session: Session):
    enricher = EnrichmentService(db_session, config=_config())
    manager = AlertManager(db_session, config=_config(cooldown_seconds=60))
    start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    ip = "203.0.113.10"

    alert = manager.handle(_event(source_ip=ip, timestamp=start))
    enriched = enricher.enrich(alert)

    rows = db_session.scalars(select(IpReputationORM)).all()
    assert len(rows) == 1
    assert rows[0].ip == ip
    first_seen = rows[0].first_seen
    assert enriched.historical_alert_count == 0

    # Second enrichment after cooldown creates a new alert; reputation row updates.
    later_alert = manager.handle(
        _event(source_ip=ip, timestamp=start + timedelta(seconds=120), attempts=22)
    )
    enricher.enrich(later_alert)

    rows = db_session.scalars(select(IpReputationORM)).all()
    assert len(rows) == 1
    assert rows[0].first_seen == first_seen
    assert rows[0].last_seen > first_seen


def test_historical_alert_count_increases(db_session: Session):
    config = _config(cooldown_seconds=30)
    manager = AlertManager(db_session, config=config)
    enricher = EnrichmentService(db_session, config=config)
    start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    ip = "198.51.100.77"

    first = manager.handle(_event(source_ip=ip, timestamp=start))
    enriched_first = enricher.enrich(first)
    assert enriched_first.historical_alert_count == 0

    second = manager.handle(
        _event(source_ip=ip, timestamp=start + timedelta(seconds=60), attempts=25)
    )
    enriched_second = enricher.enrich(second)
    assert enriched_second.historical_alert_count == 1

    third = manager.handle(
        _event(source_ip=ip, timestamp=start + timedelta(seconds=120), attempts=30)
    )
    enriched_third = enricher.enrich(third)
    assert enriched_third.historical_alert_count == 2
