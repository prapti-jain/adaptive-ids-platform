"""PCAP file replay capture source (primary capture method)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from scapy.utils import rdpcap

from backend.capture.base import PacketSource
from backend.config.settings import settings


class PcapReplaySource(PacketSource):
    """Replay packets from a ``.pcap`` / ``.pcapng`` file via Scapy.

    This is the primary capture method for AIDTIP development and testing.
    """

    def __init__(self, pcap_path: str | Path | None = None) -> None:
        """Initialize the replay source.

        Args:
            pcap_path: Path to a capture file. Defaults to ``settings.PCAP_PATH``.
        """
        self.pcap_path = Path(pcap_path or settings.PCAP_PATH)

    def capture(self) -> Iterator[Any]:
        """Read the configured PCAP and yield packets one at a time.

        Yields:
            Individual Scapy packet objects from the file.

        Raises:
            FileNotFoundError: If ``pcap_path`` does not exist.
        """
        if not self.pcap_path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        packets = rdpcap(str(self.pcap_path))
        for packet in packets:
            yield packet
