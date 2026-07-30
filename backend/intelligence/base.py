"""Abstract threat-intelligence provider interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatIntelResult:
    """Lookup result from a threat-intelligence provider.

    Attributes:
        reputation_score: Normalized score in ``[0.0, 1.0]`` (higher = worse).
        is_known_malicious: Whether the provider marks the IP as known-bad.
        geo_country: ISO-ish country code, or ``None`` if unknown.
        source: Provider identifier (e.g. ``mock``, ``virustotal``).
    """

    reputation_score: float
    is_known_malicious: bool
    geo_country: str | None
    source: str


class ThreatIntelProvider(ABC):
    """Strategy interface for IP reputation / geo lookups."""

    @abstractmethod
    def lookup(self, ip: str) -> ThreatIntelResult:
        """Look up threat intelligence for ``ip``.

        Args:
            ip: IPv4/IPv6 address string.

        Returns:
            A ``ThreatIntelResult`` for the address.
        """
