"""Port-scan detection rule."""

from __future__ import annotations

from typing import Any

from backend.detection.flow_tracker import FlowTracker
from backend.detection.rules.base import Rule
from backend.models.domain import DetectionEvent, PacketRecord


class PortScanRule(Rule):
    """Detect scanning by counting distinct destination ports per source IP."""

    rule_name = "port_scan"

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize from the ``port_scan`` section of rules.yaml."""
        section = config.get("port_scan", {})
        self.distinct_ports_threshold = int(section.get("distinct_ports_threshold", 15))
        self.window_seconds = float(section.get("window_seconds", 60))

    def evaluate(
        self,
        flow_tracker: FlowTracker,
        record: PacketRecord,
    ) -> DetectionEvent | None:
        ports = flow_tracker.destination_ports(
            record.src_ip,
            now=record.timestamp,
            window_seconds=self.window_seconds,
        )
        distinct_ports = len(ports)
        if distinct_ports <= self.distinct_ports_threshold:
            return None

        return DetectionEvent(
            rule_name=self.rule_name,
            source_ip=record.src_ip,
            target_ip=record.dst_ip,
            evidence={
                "distinct_ports": distinct_ports,
                "threshold": self.distinct_ports_threshold,
                "window_seconds": self.window_seconds,
                "target_ports": ports,
                "target_port": record.dst_port,
            },
            timestamp=record.timestamp,
        )
