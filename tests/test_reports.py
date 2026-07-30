"""Unit tests for report generation and HTML rendering."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.alerts.alert_manager import AlertManager
from backend.database.base import Base
from backend.database.models import ReportORM
from backend.models.domain import DetectionEvent
from backend.reports.html_renderer import render_report_html
from backend.reports.report_generator import ReportGenerator


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


def _config() -> dict:
    return {
        "classification": {
            "severity_bands": {
                "LOW": 0.25,
                "MEDIUM": 0.5,
                "HIGH": 0.75,
                "CRITICAL": 1.0,
            },
            "alert_cooldown_seconds": 60,
        }
    }


def _seed(session: Session) -> datetime:
    manager = AlertManager(session, config=_config())
    start = datetime(2026, 7, 30, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        DetectionEvent(
            rule_name="ssh_bruteforce",
            source_ip="10.0.0.1",
            target_ip="10.0.0.9",
            evidence={"attempts": 20, "threshold": 10, "target_port": 22},
            timestamp=start,
        ),
        DetectionEvent(
            rule_name="ssh_bruteforce",
            source_ip="10.0.0.1",
            target_ip="10.0.0.9",
            evidence={"attempts": 25, "threshold": 10, "target_port": 22},
            timestamp=start + timedelta(minutes=2),
        ),
        DetectionEvent(
            rule_name="syn_flood",
            source_ip="10.0.0.2",
            target_ip="10.0.0.9",
            evidence={"syn_count": 100, "threshold": 50, "target_port": 80},
            timestamp=start + timedelta(minutes=4),
        ),
    ]
    for event in events:
        manager.handle(event)
    return start


def test_report_generator_persists_summary(db_session: Session):
    start = _seed(db_session)
    end = start + timedelta(hours=1)

    payload = ReportGenerator(top_n=5).generate(start, end, db_session)

    assert payload["summary"]["total_alerts"] >= 2
    assert "by_severity" in payload["summary"]
    assert "by_attack_type" in payload["summary"]
    assert payload["alert_ids"]
    assert payload["generated_at"]
    assert any(a["source_ip"] == "10.0.0.1" for a in payload["top_attackers"])
    assert any(p["port"] == 22 for p in payload["top_ports"])

    rows = db_session.scalars(select(ReportORM)).all()
    assert len(rows) == 1
    assert rows[0].payload["id"] == payload["id"]


def test_html_renderer_includes_title_and_note():
    report = {
        "id": "00000000-0000-0000-0000-000000000001",
        "generated_at": "2026-07-30T12:00:00+00:00",
        "period_start": "2026-07-30T11:00:00+00:00",
        "period_end": "2026-07-30T12:00:00+00:00",
        "summary": {
            "total_alerts": 1,
            "by_severity": {"HIGH": 1},
            "by_attack_type": {"SSH_BRUTE_FORCE": 1},
        },
        "top_attackers": [{"source_ip": "10.0.0.1", "alert_count": 1}],
        "top_ports": [{"port": 22, "alert_count": 1}],
        "alerts": [
            {
                "id": "a1",
                "attack_type": "SSH_BRUTE_FORCE",
                "severity": "HIGH",
                "source_ip": "10.0.0.1",
                "target_ip": "10.0.0.9",
                "risk_score": 3.0,
                "status": "OPEN",
                "detected_at": "2026-07-30T11:30:00+00:00",
            }
        ],
        "notes": {
            "response_module": "backend/response/ is a placeholder only",
        },
    }
    html = render_report_html(report)
    assert "AIDTIP Incident Summary" in html
    assert "SSH_BRUTE_FORCE" in html
    assert "placeholder only" in html
    assert "Recommended-action column omitted" in html
