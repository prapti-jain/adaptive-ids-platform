#!/usr/bin/env python3
"""Generate a synthetic samples/sample.pcap for AIDTIP offline testing.

Uses Scapy only — no live capture or elevated privileges required.
Packet timestamps are relative to ``datetime.now()`` so default API
time windows (24h / 30d) include the generated traffic.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "samples" / "sample.pcap"

# Distinct actors so rules attribute cleanly in the pipeline.
SCANNER = "203.0.113.10"
FLOODER = "203.0.113.20"
BRUTE = "203.0.113.30"
BENIGN = "198.51.100.50"
TARGET = "198.51.100.10"
DNS = "198.51.100.53"


def _eth(src_ip: str, dst_ip: str, sport: int, dport: int, flags: str = "S"):
    return (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags=flags)
    )


def build_packets() -> list:
    packets: list = []
    # Spread attack patterns over the last ~3 minutes ending "now".
    now = datetime.now(timezone.utc)
    base = (now - timedelta(minutes=3)).timestamp()

    # --- Port scan: 25 distinct destination ports from one source ---
    for i in range(25):
        pkt = _eth(SCANNER, TARGET, sport=40000 + i, dport=1000 + i, flags="S")
        pkt.time = base + (i * 0.05)
        packets.append(pkt)

    # --- SYN flood: 120 SYNs to the same dest IP:port ---
    flood_start = base + 30.0
    for i in range(120):
        pkt = _eth(FLOODER, TARGET, sport=50000 + (i % 200), dport=80, flags="S")
        pkt.time = flood_start + (i * 0.01)
        packets.append(pkt)

    # --- SSH brute force: 18 SYNs to port 22 ---
    ssh_start = base + 90.0
    for i in range(18):
        pkt = _eth(BRUTE, TARGET, sport=41000 + i, dport=22, flags="S")
        pkt.time = ssh_start + (i * 0.2)
        packets.append(pkt)

    # --- Benign traffic: low-volume, varied ports ---
    benign_start = base + 150.0
    benign_specs = [
        (BENIGN, TARGET, 53100, 443, "PA"),
        (BENIGN, TARGET, 53101, 443, "A"),
        (BENIGN, DNS, 53102, 53, "S"),  # will be overwritten as UDP below
        (TARGET, BENIGN, 443, 53100, "A"),
        (BENIGN, TARGET, 53103, 8080, "S"),
    ]
    for i, (src, dst, sport, dport, flags) in enumerate(benign_specs):
        if dport == 53:
            pkt = (
                Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                / IP(src=src, dst=dst)
                / UDP(sport=sport, dport=dport)
            )
        else:
            pkt = _eth(src, dst, sport=sport, dport=dport, flags=flags)
        pkt.time = benign_start + i
        packets.append(pkt)

    return packets


def main() -> int:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    packets = build_packets()
    wrpcap(str(OUTPUT), packets)
    first = float(packets[0].time)
    last = float(packets[-1].time)
    print(f"Wrote {len(packets)} packets to {OUTPUT}")
    print(
        f"Timestamp range: {datetime.fromtimestamp(first, tz=timezone.utc).isoformat()} "
        f"→ {datetime.fromtimestamp(last, tz=timezone.utc).isoformat()}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
