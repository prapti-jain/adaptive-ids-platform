# Obtaining a sample PCAP for AIDTIP

Packet capture replay (`PcapReplaySource`) is the primary capture path. Point
`PCAP_PATH` in `.env` at a `.pcap` / `.pcapng` file, then iterate
`PcapReplaySource(...).capture()` and feed packets through `PacketParser.parse()`.

## Option A — Capture locally with tcpdump

```bash
# Capture 50 packets on your primary interface (macOS often uses en0)
sudo tcpdump -i en0 -c 50 -w samples/sample.pcap

# Or capture only TCP traffic to/from a host while you generate activity
sudo tcpdump -i en0 -c 100 'tcp' -w samples/sample.pcap
```

Create the `samples/` directory at the repo root if it does not exist.

## Option B — Capture an nmap scan

```bash
# Terminal 1: start the capture
sudo tcpdump -i en0 -w samples/nmap_scan.pcap

# Terminal 2: run a quick scan against a lab target you own
nmap -sS -p 1-100 127.0.0.1

# Stop tcpdump (Ctrl+C), then set:
# PCAP_PATH=samples/nmap_scan.pcap
```

## Option C — Download a public sample

Public repositories such as [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures)
and [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/) host
PCAP files suitable for offline testing. Download one into `samples/` and set
`PCAP_PATH` accordingly.

## Quick replay smoke check

```bash
# From the repo root, with the project venv active and scapy installed:
python - <<'PY'
from backend.capture.pcap_replay import PcapReplaySource
from backend.parser.packet_parser import PacketParser

for raw in PcapReplaySource("samples/sample.pcap").capture():
    record = PacketParser.parse(raw)
    if record:
        print(record)
PY
```
