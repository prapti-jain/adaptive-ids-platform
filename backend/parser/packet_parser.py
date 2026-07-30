"""Parse raw Scapy packets into normalized PacketRecord values."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP

from backend.models.domain import PacketRecord

# Scapy stores TCP flag letters; map them to readable names for detection rules.
_TCP_FLAG_NAMES: dict[str, str] = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


class PacketParser:
    """Extract IP / transport-layer fields from a Scapy packet."""

    @staticmethod
    def parse(raw_packet: Any) -> PacketRecord | None:
        """Convert a Scapy packet into a ``PacketRecord``.

        Extracts:
            - Source / destination IPs from the IP layer (required).
            - Protocol name from the transport or IP proto (TCP, UDP, ICMP, or
              a numeric fallback for other IP protocols).
            - Source / destination ports for TCP and UDP (``None`` for ICMP
              and other non-port protocols).
            - TCP control flags as a set of names (e.g. ``{"SYN", "ACK"}``);
              empty for non-TCP packets.
            - Packet size in bytes (``len(raw_packet)``).
            - Capture timestamp converted to an aware UTC ``datetime``.

        Returns ``None`` when the packet has no IP layer so callers can skip
        non-IP frames (ARP, etc.) without special-casing Scapy internals.

        Args:
            raw_packet: A Scapy packet object.

        Returns:
            A populated ``PacketRecord``, or ``None`` if there is no IP layer.
        """
        if IP not in raw_packet:
            return None

        ip_layer = raw_packet[IP]
        protocol, src_port, dst_port, flags = PacketParser._transport_fields(raw_packet)

        return PacketRecord(
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            flags=flags,
            size=len(raw_packet),
            timestamp=PacketParser._packet_timestamp(raw_packet),
        )

    @staticmethod
    def _transport_fields(
        raw_packet: Any,
    ) -> tuple[str, int | None, int | None, set[str]]:
        """Derive protocol label, ports, and TCP flags from transport layers."""
        if TCP in raw_packet:
            tcp = raw_packet[TCP]
            return "TCP", int(tcp.sport), int(tcp.dport), PacketParser._tcp_flags(tcp)

        if UDP in raw_packet:
            udp = raw_packet[UDP]
            return "UDP", int(udp.sport), int(udp.dport), set()

        if ICMP in raw_packet:
            return "ICMP", None, None, set()

        # Fall back to the IP protocol number for uncommon transports.
        return str(raw_packet[IP].proto), None, None, set()

    @staticmethod
    def _tcp_flags(tcp: Any) -> set[str]:
        """Translate Scapy TCP flag letters into a set of flag names."""
        flag_repr = str(tcp.flags)
        return {
            name
            for letter, name in _TCP_FLAG_NAMES.items()
            if letter in flag_repr
        }

    @staticmethod
    def _packet_timestamp(raw_packet: Any) -> datetime:
        """Convert Scapy's epoch ``time`` attribute to an aware UTC datetime."""
        epoch = float(getattr(raw_packet, "time", datetime.now(timezone.utc).timestamp()))
        return datetime.fromtimestamp(epoch, tz=timezone.utc)
