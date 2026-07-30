"""Abstract packet capture source."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any


class PacketSource(ABC):
    """Abstract base for sources that yield raw Scapy packets."""

    @abstractmethod
    def capture(self) -> Iterator[Any]:
        """Yield raw Scapy packets from the underlying source.

        Returns:
            An iterator of Scapy packet objects (typically ``Packet``).
        """
