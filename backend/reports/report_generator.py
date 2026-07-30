"""Generate and persist period incident reports from alerts."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import AlertORM, ReportORM


def ports_from_evidence(evidence: dict[str, Any] | None) -> set[int]:
    """Collect destination ports from ``target_port`` and/or ``target_ports``."""
    ports: set[int] = set()
    if not evidence:
        return ports

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


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class ReportGenerator:
    """Build structured reports over an alert time window and persist them."""

    def __init__(self, *, top_n: int = 10) -> None:
        self.top_n = top_n

    def generate(
        self,
        start: datetime,
        end: datetime,
        db_session: Session,
    ) -> dict[str, Any]:
        """Produce a report for ``[start, end]``, persist it, and return the dict.

        The returned payload includes summary counts, top attackers/ports,
        included alert IDs, and ``generated_at``.
        """
        start = _ensure_aware(start)
        end = _ensure_aware(end)
        if end < start:
            raise ValueError("end must be >= start")

        rows = db_session.scalars(
            select(AlertORM)
            .where(AlertORM.detected_at >= start, AlertORM.detected_at <= end)
            .order_by(AlertORM.detected_at.asc())
        ).all()

        by_severity: Counter[str] = Counter()
        by_attack_type: Counter[str] = Counter()
        attacker_counts: Counter[str] = Counter()
        port_counts: Counter[int] = Counter()
        alert_ids: list[str] = []

        for row in rows:
            by_severity[row.severity] += 1
            by_attack_type[row.attack_type] += 1
            attacker_counts[row.source_ip] += 1
            alert_ids.append(str(row.id))
            for port in ports_from_evidence(row.evidence or {}):
                port_counts[port] += 1

        generated_at = datetime.now(timezone.utc)
        report_id = uuid4()

        payload: dict[str, Any] = {
            "id": str(report_id),
            "generated_at": generated_at.isoformat(),
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
            "summary": {
                "total_alerts": len(rows),
                "by_severity": dict(by_severity),
                "by_attack_type": dict(by_attack_type),
            },
            "top_attackers": [
                {"source_ip": ip, "alert_count": count}
                for ip, count in attacker_counts.most_common(self.top_n)
            ],
            "top_ports": [
                {"port": port, "alert_count": count}
                for port, count in port_counts.most_common(self.top_n)
            ],
            "alert_ids": alert_ids,
            "alerts": [
                {
                    "id": str(row.id),
                    "attack_type": row.attack_type,
                    "severity": row.severity,
                    "source_ip": row.source_ip,
                    "target_ip": row.target_ip,
                    "risk_score": row.risk_score,
                    "status": row.status,
                    "detected_at": (
                        row.detected_at.isoformat()
                        if row.detected_at.tzinfo
                        else row.detected_at.replace(tzinfo=timezone.utc).isoformat()
                    ),
                }
                for row in rows
            ],
            "notes": {
                "response_module": (
                    "backend/response/ is a placeholder only — automated "
                    "response / recommended-action advisor is not implemented."
                ),
            },
        }

        orm = ReportORM(
            id=report_id,
            period_start=start,
            period_end=end,
            generated_at=generated_at,
            payload=payload,
        )
        db_session.add(orm)
        db_session.commit()
        db_session.refresh(orm)
        return payload
