"""SSH brute-force detection rule."""

from __future__ import annotations

from typing import Any

from backend.detection.flow_tracker import FlowTracker
from backend.detection.rules.base import Rule
from backend.models.domain import DetectionEvent, PacketRecord


class SshBruteForceRule(Rule):
    """Detect SSH brute force via repeated attempts to the SSH port."""

    rule_name = "ssh_bruteforce"

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize from the ``ssh_bruteforce`` section of rules.yaml."""
        section = config.get("ssh_bruteforce", {})
        self.attempt_threshold = int(section.get("attempt_threshold", 10))
        self.window_seconds = float(section.get("window_seconds", 60))
        self.target_port = int(section.get("target_port", 22))

    def evaluate(
        self,
        flow_tracker: FlowTracker,
        record: PacketRecord,
    ) -> DetectionEvent | None:
        if record.dst_port != self.target_port:
            return None

        attempts = flow_tracker.destination_port_count(
            record.src_ip,
            self.target_port,
            now=record.timestamp,
            window_seconds=self.window_seconds,
        )
        if attempts <= self.attempt_threshold:
            return None

        return DetectionEvent(
            rule_name=self.rule_name,
            source_ip=record.src_ip,
            target_ip=record.dst_ip,
            evidence={
                "attempts": attempts,
                "threshold": self.attempt_threshold,
                "target_port": self.target_port,
                "window_seconds": self.window_seconds,
            },
            timestamp=record.timestamp,
        )
