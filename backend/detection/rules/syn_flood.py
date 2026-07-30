"""SYN-flood detection rule."""

from __future__ import annotations

from typing import Any

from backend.detection.flow_tracker import FlowTracker
from backend.detection.rules.base import Rule
from backend.models.domain import DetectionEvent, PacketRecord


class SynFloodRule(Rule):
    """Detect SYN floods by counting SYN-flagged packets per source IP."""

    rule_name = "syn_flood"

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize from the ``syn_flood`` section of rules.yaml."""
        section = config.get("syn_flood", {})
        self.syn_count_threshold = int(section.get("syn_count_threshold", 50))
        self.window_seconds = float(section.get("window_seconds", 10))

    def evaluate(
        self,
        flow_tracker: FlowTracker,
        record: PacketRecord,
    ) -> DetectionEvent | None:
        if "SYN" not in record.flags:
            return None

        syn_count = flow_tracker.syn_count(
            record.src_ip,
            now=record.timestamp,
            window_seconds=self.window_seconds,
        )
        if syn_count <= self.syn_count_threshold:
            return None

        return DetectionEvent(
            rule_name=self.rule_name,
            source_ip=record.src_ip,
            target_ip=record.dst_ip,
            evidence={
                "syn_count": syn_count,
                "threshold": self.syn_count_threshold,
                "window_seconds": self.window_seconds,
                "packet_rate": flow_tracker.packet_rate(
                    record.src_ip,
                    now=record.timestamp,
                    window_seconds=self.window_seconds,
                ),
                "target_port": record.dst_port,
            },
            timestamp=record.timestamp,
        )
