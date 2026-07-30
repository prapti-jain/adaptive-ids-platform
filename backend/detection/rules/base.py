"""Abstract detection rule."""

from __future__ import annotations

from abc import ABC, abstractmethod

from backend.detection.flow_tracker import FlowTracker
from backend.models.domain import DetectionEvent, PacketRecord


class Rule(ABC):
    """Strategy interface for a single detection rule."""

    @abstractmethod
    def evaluate(
        self,
        flow_tracker: FlowTracker,
        record: PacketRecord,
    ) -> DetectionEvent | None:
        """Evaluate traffic state after ``record`` was tracked.

        Args:
            flow_tracker: Shared sliding-window flow state.
            record: The packet that was just ingested.

        Returns:
            A ``DetectionEvent`` when the rule matches, otherwise ``None``.
        """
