"""Sliding-window per-source flow state for detection rules."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from backend.models.domain import PacketRecord


@dataclass(frozen=True)
class _PacketEvent:
    """Minimal fields retained inside the sliding window."""

    timestamp: datetime
    dst_ip: str
    dst_port: int | None
    flags: frozenset[str]


class FlowTracker:
    """In-memory sliding-window counters keyed by source IP.

    Tracks distinct destination ports, SYN counts, destination-port hit
    counts, and packet rate within a configurable time window.
    """

    def __init__(self, window_seconds: float) -> None:
        """Initialize the tracker.

        Args:
            window_seconds: Retention / default analysis window size.
        """
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = float(window_seconds)
        self._events: dict[str, deque[_PacketEvent]] = defaultdict(deque)

    def track_packet(self, record: PacketRecord) -> None:
        """Record a packet and prune events that fall outside the window."""
        event = _PacketEvent(
            timestamp=record.timestamp,
            dst_ip=record.dst_ip,
            dst_port=record.dst_port,
            flags=frozenset(record.flags),
        )
        self._events[record.src_ip].append(event)
        self.prune_expired(now=record.timestamp)

    def prune_expired(self, now: datetime | None = None) -> None:
        """Drop per-source events older than the retention window.

        Args:
            now: Reference time for expiry. Defaults to current UTC time.
        """
        reference = now or datetime.now(timezone.utc)
        cutoff = reference - timedelta(seconds=self.window_seconds)
        empty_keys: list[str] = []

        for src_ip, events in self._events.items():
            while events and events[0].timestamp < cutoff:
                events.popleft()
            if not events:
                empty_keys.append(src_ip)

        for src_ip in empty_keys:
            del self._events[src_ip]

    def distinct_destination_ports(
        self,
        src_ip: str,
        *,
        now: datetime,
        window_seconds: float | None = None,
    ) -> int:
        """Count distinct destination ports touched by ``src_ip`` in the window."""
        return len(self.destination_ports(src_ip, now=now, window_seconds=window_seconds))

    def destination_ports(
        self,
        src_ip: str,
        *,
        now: datetime,
        window_seconds: float | None = None,
    ) -> list[int]:
        """Return sorted distinct destination ports touched by ``src_ip``."""
        ports = {
            event.dst_port
            for event in self._events_in_window(src_ip, now=now, window_seconds=window_seconds)
            if event.dst_port is not None
        }
        return sorted(ports)

    def syn_count(
        self,
        src_ip: str,
        *,
        now: datetime,
        window_seconds: float | None = None,
    ) -> int:
        """Count packets from ``src_ip`` that include the SYN flag."""
        return sum(
            1
            for event in self._events_in_window(src_ip, now=now, window_seconds=window_seconds)
            if "SYN" in event.flags
        )

    def destination_port_count(
        self,
        src_ip: str,
        port: int,
        *,
        now: datetime,
        window_seconds: float | None = None,
    ) -> int:
        """Count packets from ``src_ip`` destined to ``port`` in the window."""
        return sum(
            1
            for event in self._events_in_window(src_ip, now=now, window_seconds=window_seconds)
            if event.dst_port == port
        )

    def packet_rate(
        self,
        src_ip: str,
        *,
        now: datetime,
        window_seconds: float | None = None,
    ) -> float:
        """Return packets/sec for ``src_ip`` over the analysis window."""
        window = self.window_seconds if window_seconds is None else float(window_seconds)
        if window <= 0:
            return 0.0
        count = len(self._events_in_window(src_ip, now=now, window_seconds=window))
        return count / window

    def _events_in_window(
        self,
        src_ip: str,
        *,
        now: datetime,
        window_seconds: float | None,
    ) -> list[_PacketEvent]:
        window = self.window_seconds if window_seconds is None else float(window_seconds)
        cutoff = now - timedelta(seconds=window)
        return [event for event in self._events.get(src_ip, ()) if event.timestamp >= cutoff]
