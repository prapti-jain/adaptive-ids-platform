"""API layer tests using FastAPI TestClient."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.alerts.alert_manager import AlertManager
from backend.database.base import Base
from backend.database.session import get_db
from backend.intelligence.enrichment_service import EnrichmentService
from backend.main import app
from backend.models.domain import DetectionEvent


@pytest.fixture()
def client_and_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        session = TestingSessionLocal()
        try:
            yield client, session
        finally:
            session.close()
    app.dependency_overrides.clear()
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
        },
        "intelligence": {"provider": "mock"},
    }


def _seed_alerts(session: Session) -> list:
    manager = AlertManager(session, config=_config())
    enricher = EnrichmentService(session, config=_config())
    start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    alerts = []
    for index, source in enumerate(("10.0.0.1", "10.0.0.2")):
        event = DetectionEvent(
            rule_name="ssh_bruteforce",
            source_ip=source,
            target_ip="10.0.0.22",
            evidence={"attempts": 20, "threshold": 10, "target_port": 22},
            timestamp=start.replace(minute=index),
        )
        alert = manager.handle(event)
        enricher.enrich(alert)
        alerts.append(alert)
    return alerts


def test_health(client_and_session):
    client, _ = client_and_session
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_list_alerts_returns_seeded_items(client_and_session):
    client, session = client_and_session
    seeded = _seed_alerts(session)
    response = client.get("/api/alerts")
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == len(seeded)
    assert len(payload["items"]) == len(seeded)
    assert "alert" in payload["items"][0]
    assert "ip_reputation" in payload["items"][0]


def test_patch_alert_status(client_and_session):
    client, session = client_and_session
    seeded = _seed_alerts(session)
    alert_id = seeded[0].id

    response = client.patch(
        f"/api/alerts/{alert_id}/status",
        json={"status": "INVESTIGATING"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["alert"]["status"] == "INVESTIGATING"
    assert body["alert"]["id"] == str(alert_id)

    detail = client.get(f"/api/alerts/{alert_id}")
    assert detail.status_code == 200
    assert detail.json()["alert"]["status"] == "INVESTIGATING"


def test_websocket_receives_status_broadcast(client_and_session):
    client, session = client_and_session
    seeded = _seed_alerts(session)
    alert_id = seeded[0].id

    with client.websocket_connect("/ws/alerts") as websocket:
        response = client.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": "RESOLVED"},
        )
        assert response.status_code == 200
        message = websocket.receive_json()
        assert message["alert"]["id"] == str(alert_id)
        assert message["alert"]["status"] == "RESOLVED"
        assert "ip_reputation" in message
