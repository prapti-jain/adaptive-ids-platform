"""Unit tests for Scorer classification."""

from datetime import datetime, timezone

from backend.classification.scorer import Scorer, SEVERITY_WEIGHTS
from backend.models.domain import AttackType, DetectionEvent, Severity


def _event(
    *,
    rule_name: str,
    metric_key: str,
    observed: float,
    threshold: float,
) -> DetectionEvent:
    return DetectionEvent(
        rule_name=rule_name,
        source_ip="10.0.0.50",
        target_ip="10.0.0.1",
        evidence={
            metric_key: observed,
            "threshold": threshold,
        },
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
    )


def test_scorer_maps_rule_and_scores_near_threshold_as_low():
    scorer = Scorer(
        {
            "classification": {
                "severity_bands": {
                    "LOW": 0.25,
                    "MEDIUM": 0.5,
                    "HIGH": 0.75,
                    "CRITICAL": 1.0,
                }
            }
        }
    )
    # Just above threshold → low confidence / LOW severity.
    alert = scorer.classify(
        _event(
            rule_name="port_scan",
            metric_key="distinct_ports",
            observed=16,
            threshold=15,
        )
    )

    assert alert.attack_type == AttackType.PORT_SCAN
    assert 0.0 < alert.confidence < 0.25
    assert alert.severity == Severity.LOW
    assert alert.risk_score == SEVERITY_WEIGHTS[Severity.LOW] * alert.confidence
    assert alert.status.value == "OPEN"


def test_scorer_high_excess_yields_critical_severity():
    scorer = Scorer(
        {
            "classification": {
                "severity_bands": {
                    "LOW": 0.25,
                    "MEDIUM": 0.5,
                    "HIGH": 0.75,
                    "CRITICAL": 1.0,
                }
            }
        }
    )
    # 2x threshold → confidence 1.0 → CRITICAL.
    alert = scorer.classify(
        _event(
            rule_name="syn_flood",
            metric_key="syn_count",
            observed=100,
            threshold=50,
        )
    )

    assert alert.attack_type == AttackType.SYN_FLOOD
    assert alert.confidence == 1.0
    assert alert.severity == Severity.CRITICAL
    assert alert.risk_score == 9.0


def test_scorer_medium_band_for_moderate_excess():
    scorer = Scorer(
        {
            "classification": {
                "severity_bands": {
                    "LOW": 0.25,
                    "MEDIUM": 0.5,
                    "HIGH": 0.75,
                    "CRITICAL": 1.0,
                }
            }
        }
    )
    # excess_ratio = (14 - 10) / 10 = 0.4 → MEDIUM
    alert = scorer.classify(
        _event(
            rule_name="ssh_bruteforce",
            metric_key="attempts",
            observed=14,
            threshold=10,
        )
    )

    assert alert.attack_type == AttackType.SSH_BRUTE_FORCE
    assert alert.confidence == 0.4
    assert alert.severity == Severity.MEDIUM
    assert alert.risk_score == SEVERITY_WEIGHTS[Severity.MEDIUM] * 0.4
