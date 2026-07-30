"""Classify DetectionEvents into scored Alerts."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from backend.config.settings import load_rules_config
from backend.models.domain import (
    Alert,
    AlertStatus,
    AttackType,
    DetectionEvent,
    Severity,
)

RULE_TO_ATTACK_TYPE: dict[str, AttackType] = {
    "port_scan": AttackType.PORT_SCAN,
    "syn_flood": AttackType.SYN_FLOOD,
    "ssh_bruteforce": AttackType.SSH_BRUTE_FORCE,
}

# Evidence keys that hold the observed counter for each rule.
RULE_METRIC_KEYS: dict[str, str] = {
    "port_scan": "distinct_ports",
    "syn_flood": "syn_count",
    "ssh_bruteforce": "attempts",
}

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.LOW: 1.0,
    Severity.MEDIUM: 3.0,
    Severity.HIGH: 6.0,
    Severity.CRITICAL: 9.0,
}

_DEFAULT_BANDS: dict[str, float] = {
    "LOW": 0.25,
    "MEDIUM": 0.5,
    "HIGH": 0.75,
    "CRITICAL": 1.0,
}


class Scorer:
    """Map detection events to scored alerts using configurable severity bands."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize from rules.yaml ``classification`` section (or override)."""
        full_config = config if config is not None else load_rules_config()
        classification = full_config.get("classification", {})
        bands = classification.get("severity_bands", _DEFAULT_BANDS)
        self.severity_bands = {
            Severity.LOW: float(bands.get("LOW", _DEFAULT_BANDS["LOW"])),
            Severity.MEDIUM: float(bands.get("MEDIUM", _DEFAULT_BANDS["MEDIUM"])),
            Severity.HIGH: float(bands.get("HIGH", _DEFAULT_BANDS["HIGH"])),
            Severity.CRITICAL: float(bands.get("CRITICAL", _DEFAULT_BANDS["CRITICAL"])),
        }

    def classify(self, event: DetectionEvent) -> Alert:
        """Build an ``Alert`` from a ``DetectionEvent``.

        Confidence rises as the observed metric exceeds the rule threshold
        (just over threshold → low; far past → high, capped at 1.0). Severity
        is chosen from configurable confidence bands; risk score is
        ``severity_weight * confidence``.
        """
        attack_type = RULE_TO_ATTACK_TYPE.get(event.rule_name)
        if attack_type is None:
            raise ValueError(f"Unknown rule_name for classification: {event.rule_name}")

        confidence = self._confidence(event)
        severity = self._severity_from_confidence(confidence)
        risk_score = SEVERITY_WEIGHTS[severity] * confidence

        return Alert(
            id=uuid4(),
            rule_name=event.rule_name,
            attack_type=attack_type,
            source_ip=event.source_ip,
            target_ip=event.target_ip,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            status=AlertStatus.OPEN,
            evidence=dict(event.evidence),
            detected_at=event.timestamp,
        )

    def _confidence(self, event: DetectionEvent) -> float:
        """Compute 0–1 confidence from how far evidence exceeds the threshold."""
        metric_key = RULE_METRIC_KEYS.get(event.rule_name)
        if metric_key is None:
            return 0.0

        observed = float(event.evidence.get(metric_key, 0))
        threshold = float(event.evidence.get("threshold", 0))
        if threshold <= 0:
            return 1.0 if observed > 0 else 0.0

        # Just above threshold → near 0; 2x threshold → 1.0.
        excess_ratio = (observed - threshold) / threshold
        return min(1.0, max(0.0, excess_ratio))

    def _severity_from_confidence(self, confidence: float) -> Severity:
        """Map confidence into a severity band using configured upper bounds."""
        if confidence < self.severity_bands[Severity.LOW]:
            return Severity.LOW
        if confidence < self.severity_bands[Severity.MEDIUM]:
            return Severity.MEDIUM
        if confidence < self.severity_bands[Severity.HIGH]:
            return Severity.HIGH
        return Severity.CRITICAL
