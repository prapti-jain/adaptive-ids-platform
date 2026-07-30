"""Deterministic offline mock threat-intelligence provider."""

from __future__ import annotations

import hashlib

from backend.intelligence.base import ThreatIntelProvider, ThreatIntelResult

# ---------------------------------------------------------------------------
# Known-malicious test IPs (for demos and unit tests)
# ---------------------------------------------------------------------------
# These addresses are ALWAYS flagged malicious by MockThreatIntelProvider.
# Several match actors in scripts/generate_sample_pcap.py so the sample PCAP
# pipeline demonstrates the malicious-IP enrichment path:
#
#   203.0.113.20  — sample SYN flooder (FLOODER)
#   203.0.113.30  — sample SSH brute actor (BRUTE)
#   198.51.100.66 — extra standalone demo IP (not in the sample PCAP)
#
KNOWN_MALICIOUS_IPS: frozenset[str] = frozenset(
    {
        "203.0.113.20",
        "203.0.113.30",
        "198.51.100.66",
    }
)

# Small fixed country list for stable geo assignment from the IP hash.
_COUNTRIES: tuple[str | None, ...] = (
    "US",
    "DE",
    "CN",
    "RU",
    "BR",
    "IN",
    "GB",
    "JP",
    None,
)


class MockThreatIntelProvider(ThreatIntelProvider):
    """Offline provider that derives reproducible intel from the IP string.

    No network calls. The same IP always yields the same
    ``ThreatIntelResult`` across process restarts.
    """

    source = "mock"

    def lookup(self, ip: str) -> ThreatIntelResult:
        """Return deterministic fake reputation/geo data for ``ip``."""
        if ip in KNOWN_MALICIOUS_IPS:
            return ThreatIntelResult(
                reputation_score=0.95,
                is_known_malicious=True,
                geo_country=self._geo_from_hash(ip),
                source=self.source,
            )

        digest = hashlib.sha256(ip.encode("utf-8")).hexdigest()
        # Map first 8 hex chars to a stable float in [0.0, 1.0).
        reputation_score = int(digest[:8], 16) / 0x100000000
        return ThreatIntelResult(
            reputation_score=reputation_score,
            is_known_malicious=False,
            geo_country=self._geo_from_hash(ip, digest=digest),
            source=self.source,
        )

    @staticmethod
    def _geo_from_hash(ip: str, digest: str | None = None) -> str | None:
        digest = digest or hashlib.sha256(ip.encode("utf-8")).hexdigest()
        index = int(digest[8:10], 16) % len(_COUNTRIES)
        return _COUNTRIES[index]
