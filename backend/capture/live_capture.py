"""Live network interface capture source (secondary / bonus)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from scapy.sendrecv import sniff

from backend.capture.base import PacketSource
from backend.config.settings import settings


class LiveCaptureSource(PacketSource):
    """Capture packets from a live network interface via ``scapy.sniff``.

    Requires elevated privileges (e.g. root / Administrator) on most systems.
    Treat this as a secondary capture path; prefer ``PcapReplaySource`` for
    development and deterministic tests.
    """

    def __init__(self, interface: str | None = None, count: int = 0) -> None:
        """Initialize the live capture source.

        Args:
            interface: Interface name (e.g. ``eth0``, ``en0``). Defaults to
                ``settings.CAPTURE_INTERFACE``.
            count: Number of packets to capture. ``0`` means capture until
                interrupted (Scapy default).
        """
        self.interface = interface or settings.CAPTURE_INTERFACE
        self.count = count

    def capture(self) -> Iterator[Any]:
        """Sniff packets on ``self.interface`` and yield them one at a time.

        Yields:
            Individual Scapy packet objects from the live interface.
        """
        packets = sniff(iface=self.interface, count=self.count, store=True)
        for packet in packets:
            yield packet
