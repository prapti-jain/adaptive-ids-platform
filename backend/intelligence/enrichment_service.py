"""Threat-intelligence enrichment orchestration."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.config.settings import load_rules_config
from backend.database.models import AlertORM, IpReputationORM
from backend.intelligence.base import ThreatIntelProvider, ThreatIntelResult
from backend.intelligence.mock_provider import MockThreatIntelProvider
from backend.models.domain import Alert, EnrichedAlert


def reputation_label(score: float, *, is_known_malicious: bool) -> str:
    """Map a numeric reputation score to a coarse label."""
    if is_known_malicious or score >= 0.7:
        return "malicious"
    if score >= 0.3:
        return "suspicious"
    return "clean"


def build_provider(config: dict[str, Any] | None = None) -> ThreatIntelProvider:
    """Instantiate the configured threat-intel provider.

    Controlled by ``intelligence.provider`` in rules.yaml. Currently only
    ``mock`` is implemented; swap the config value later to select a real
    provider without changing call sites.
    """
    full_config = config if config is not None else load_rules_config()
    name = str(full_config.get("intelligence", {}).get("provider", "mock")).lower()
    if name == "mock":
        return MockThreatIntelProvider()
    raise ValueError(f"Unsupported intelligence.provider: {name!r}")


class EnrichmentService:
    """Enrich alerts with provider intel + local historical context."""

    def __init__(
        self,
        session: Session,
        provider: ThreatIntelProvider | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.session = session
        self.provider = provider or build_provider(config)

    def enrich(self, alert: Alert) -> EnrichedAlert:
        """Look up intel for ``alert.source_ip``, upsert cache, return enriched alert.

        Historical count is the number of *prior* alerts for the same
        ``source_ip`` (excluding the current alert id).
        """
        result = self.provider.lookup(alert.source_ip)
        self._upsert_reputation(alert.source_ip, result, seen_at=alert.detected_at)
        historical = self._historical_alert_count(alert)

        return EnrichedAlert(
            alert=alert,
            ip_reputation=reputation_label(
                result.reputation_score,
                is_known_malicious=result.is_known_malicious,
            ),
            geo_country=result.geo_country,
            is_known_malicious=result.is_known_malicious,
            historical_alert_count=historical,
        )

    def attach_cached_enrichment(self, alert: Alert) -> EnrichedAlert:
        """Build an ``EnrichedAlert`` from the ``ip_reputation`` cache (read-only).

        Does not call the external/mock provider or upsert. Missing cache rows
        yield ``ip_reputation="unknown"``.
        """
        historical = self._historical_alert_count(alert)
        row = self.session.get(IpReputationORM, alert.source_ip)
        if row is None:
            return EnrichedAlert(
                alert=alert,
                ip_reputation="unknown",
                geo_country=None,
                is_known_malicious=False,
                historical_alert_count=historical,
            )
        return EnrichedAlert(
            alert=alert,
            ip_reputation=reputation_label(
                row.reputation_score,
                is_known_malicious=row.is_known_malicious,
            ),
            geo_country=row.geo_country,
            is_known_malicious=row.is_known_malicious,
            historical_alert_count=historical,
        )

    def _upsert_reputation(
        self,
        ip: str,
        result: ThreatIntelResult,
        *,
        seen_at: datetime,
    ) -> None:
        """Insert or update the ``ip_reputation`` cache row for ``ip``."""
        now = seen_at if seen_at.tzinfo else seen_at.replace(tzinfo=timezone.utc)
        existing = self.session.get(IpReputationORM, ip)
        if existing is None:
            self.session.add(
                IpReputationORM(
                    ip=ip,
                    reputation_score=result.reputation_score,
                    is_known_malicious=result.is_known_malicious,
                    geo_country=result.geo_country,
                    first_seen=now,
                    last_seen=now,
                    source=result.source,
                )
            )
        else:
            existing.reputation_score = result.reputation_score
            existing.is_known_malicious = result.is_known_malicious
            existing.geo_country = result.geo_country
            existing.last_seen = now
            existing.source = result.source
            self.session.add(existing)
        self.session.commit()

    def _historical_alert_count(self, alert: Alert) -> int:
        """Count alerts for ``source_ip`` excluding the current alert."""
        stmt = (
            select(func.count())
            .select_from(AlertORM)
            .where(
                AlertORM.source_ip == alert.source_ip,
                AlertORM.id != alert.id,
            )
        )
        return int(self.session.scalar(stmt) or 0)
