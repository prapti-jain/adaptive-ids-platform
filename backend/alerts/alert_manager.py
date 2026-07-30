"""Alert deduplication and persistence."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.alerts.mappers import alert_from_orm, alert_to_orm
from backend.classification.scorer import Scorer
from backend.config.settings import load_rules_config
from backend.database.models import AlertORM
from backend.models.domain import Alert, AttackType, DetectionEvent


class AlertManager:
    """Classify detection events, deduplicate by cooldown, and persist alerts."""

    def __init__(
        self,
        session: Session,
        scorer: Scorer | None = None,
        cooldown_seconds: float | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        """Create a manager bound to a SQLAlchemy session.

        Args:
            session: Active DB session used for reads/writes.
            scorer: Optional scorer override (defaults to rules.yaml bands).
            cooldown_seconds: Dedup window for (source_ip, attack_type).
            config: Optional rules config override (useful in tests).
        """
        full_config = config if config is not None else load_rules_config()
        classification = full_config.get("classification", {})
        self.session = session
        self.scorer = scorer or Scorer(full_config)
        self.cooldown_seconds = float(
            cooldown_seconds
            if cooldown_seconds is not None
            else classification.get("alert_cooldown_seconds", 60)
        )

    def handle(self, event: DetectionEvent) -> Alert:
        """Classify ``event``, deduplicate within the cooldown, and persist.

        If an alert already exists for the same ``(source_ip, attack_type)``
        with ``detected_at`` inside the cooldown window, its evidence and
        timestamp (and scores) are updated in place. Otherwise a new row is
        inserted.
        """
        candidate = self.scorer.classify(event)
        existing = self._find_within_cooldown(
            source_ip=candidate.source_ip,
            attack_type=candidate.attack_type,
            detected_at=candidate.detected_at,
        )

        if existing is not None:
            existing.evidence = dict(candidate.evidence)
            existing.detected_at = candidate.detected_at
            existing.target_ip = candidate.target_ip
            existing.confidence = candidate.confidence
            existing.severity = candidate.severity.value
            existing.risk_score = candidate.risk_score
            existing.rule_name = candidate.rule_name
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return alert_from_orm(existing)

        orm = alert_to_orm(candidate)
        self.session.add(orm)
        self.session.commit()
        self.session.refresh(orm)
        return alert_from_orm(orm)

    def get(self, alert_id: UUID) -> Alert | None:
        """Fetch a single alert by id, or ``None`` if missing."""
        orm = self.session.get(AlertORM, alert_id)
        return alert_from_orm(orm) if orm is not None else None

    def _find_within_cooldown(
        self,
        *,
        source_ip: str,
        attack_type: AttackType,
        detected_at: datetime,
    ) -> AlertORM | None:
        cutoff = detected_at - timedelta(seconds=self.cooldown_seconds)
        stmt = (
            select(AlertORM)
            .where(
                AlertORM.source_ip == source_ip,
                AlertORM.attack_type == attack_type.value,
                AlertORM.detected_at >= cutoff,
            )
            .order_by(AlertORM.detected_at.desc())
            .limit(1)
        )
        return self.session.scalars(stmt).first()
