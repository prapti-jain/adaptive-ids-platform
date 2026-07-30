"""Unit tests for PacketParser."""

from datetime import timezone

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from backend.parser.packet_parser import PacketParser


def test_parse_ip_tcp_packet():
    """Parser extracts IP/TCP fields into a PacketRecord."""
    raw = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=54321, dport=80, flags="SA")
    )
    raw.time = 1_700_000_000.0
    expected_size = len(bytes(raw))

    record = PacketParser.parse(raw)

    assert record is not None
    assert record.src_ip == "10.0.0.1"
    assert record.dst_ip == "10.0.0.2"
    assert record.protocol == "TCP"
    assert record.src_port == 54321
    assert record.dst_port == 80
    assert record.flags == {"SYN", "ACK"}
    assert record.size == expected_size
    assert record.timestamp.tzinfo == timezone.utc
    assert record.timestamp.timestamp() == 1_700_000_000.0


def test_parse_returns_none_without_ip_layer():
    """Non-IP frames are skipped."""
    raw = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")

    assert PacketParser.parse(raw) is None
