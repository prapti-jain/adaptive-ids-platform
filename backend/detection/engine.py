"""Orchestrates flow tracking and rule evaluation."""

from __future__ import annotations

from backend.config.settings import load_rules_config
from backend.detection.flow_tracker import FlowTracker
from backend.detection.rules.base import Rule
from backend.detection.rules.port_scan import PortScanRule
from backend.detection.rules.ssh_bruteforce import SshBruteForceRule
from backend.detection.rules.syn_flood import SynFloodRule
from backend.models.domain import DetectionEvent, PacketRecord


class DetectionEngine:
    """Feed packet records through a FlowTracker and configured Rule set."""

    def __init__(
        self,
        rules: list[Rule] | None = None,
        flow_tracker: FlowTracker | None = None,
        rules_config: dict | None = None,
    ) -> None:
        """Create an engine with optional injected rules/tracker for tests.

        When omitted, loads ``backend/config/rules.yaml`` via settings and
        instantiates the default three rules plus a FlowTracker whose
        retention window covers the longest configured rule window.
        """
        config = rules_config if rules_config is not None else load_rules_config()
        self.rules = rules if rules is not None else self._default_rules(config)
        self.flow_tracker = flow_tracker or FlowTracker(
            window_seconds=self._retention_window(config, self.rules)
        )

    def process(self, record: PacketRecord) -> list[DetectionEvent]:
        """Track ``record`` then evaluate every rule.

        Returns:
            Zero or more ``DetectionEvent`` values from matching rules.
        """
        self.flow_tracker.track_packet(record)
        events: list[DetectionEvent] = []
        for rule in self.rules:
            event = rule.evaluate(self.flow_tracker, record)
            if event is not None:
                events.append(event)
        return events

    @staticmethod
    def _default_rules(config: dict) -> list[Rule]:
        return [
            PortScanRule(config),
            SynFloodRule(config),
            SshBruteForceRule(config),
        ]

    @staticmethod
    def _retention_window(config: dict, rules: list[Rule]) -> float:
        configured = float(config.get("flow_tracker", {}).get("window_seconds", 60))
        rule_windows = [
            float(getattr(rule, "window_seconds", configured))
            for rule in rules
        ]
        return max([configured, *rule_windows])
