"""Domain models for AIDTIP packet processing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID


class AttackType(str, Enum):
    """Attack categories corresponding to Phase 3 detection rules."""

    PORT_SCAN = "PORT_SCAN"
    SYN_FLOOD = "SYN_FLOOD"
    SSH_BRUTE_FORCE = "SSH_BRUTE_FORCE"


class Severity(str, Enum):
    """Alert severity levels derived from classification confidence."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    """Lifecycle status of a persisted alert."""

    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class PacketRecord:
    """Normalized representation of a captured IP packet.

    Captures the fields the detection and classification pipelines need
    without depending on Scapy packet objects downstream.
    """

    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    flags: set[str]
    size: int
    timestamp: datetime


@dataclass
class DetectionEvent:
    """Event produced when a detection rule matches observed traffic.

    Attributes:
        rule_name: Identifier of the rule that fired (e.g. ``port_scan``).
        source_ip: Attacker / source address that triggered the rule.
        target_ip: Optional victim / destination address when applicable.
        evidence: Structured details (counts, thresholds, ports, etc.).
        timestamp: Time associated with the triggering observation.
    """

    rule_name: str
    source_ip: str
    target_ip: str | None
    evidence: dict[str, Any]
    timestamp: datetime


@dataclass
class Alert:
    """Classified, persistable alert derived from a DetectionEvent."""

    id: UUID
    rule_name: str
    attack_type: AttackType
    source_ip: str
    target_ip: str | None
    severity: Severity
    confidence: float
    risk_score: float
    status: AlertStatus
    evidence: dict[str, Any]
    detected_at: datetime


@dataclass
class EnrichedAlert:
    """Alert wrapped with threat-intelligence and local history context."""

    alert: Alert
    ip_reputation: str
    geo_country: str | None
    is_known_malicious: bool
    historical_alert_count: int
