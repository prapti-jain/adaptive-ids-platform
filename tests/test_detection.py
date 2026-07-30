"""Unit tests for the detection engine and rules."""

from datetime import datetime, timedelta, timezone

from backend.detection.engine import DetectionEngine
from backend.models.domain import PacketRecord


def _base_time() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _packet(
    *,
    src_ip: str = "10.0.0.50",
    dst_ip: str = "10.0.0.1",
    protocol: str = "TCP",
    src_port: int = 40000,
    dst_port: int = 80,
    flags: set[str] | None = None,
    timestamp: datetime | None = None,
) -> PacketRecord:
    return PacketRecord(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        flags=flags if flags is not None else {"SYN"},
        size=60,
        timestamp=timestamp or _base_time(),
    )


def _engine_with_low_thresholds() -> DetectionEngine:
    """Engine with low thresholds so synthetic bursts trip cleanly."""
    config = {
        "flow_tracker": {"window_seconds": 60},
        "port_scan": {"distinct_ports_threshold": 15, "window_seconds": 60},
        "syn_flood": {"syn_count_threshold": 20, "window_seconds": 60},
        "ssh_bruteforce": {
            "attempt_threshold": 10,
            "window_seconds": 60,
            "target_port": 22,
        },
    }
    return DetectionEngine(rules_config=config)


def test_port_scan_rule_triggers_on_many_distinct_ports():
    engine = _engine_with_low_thresholds()
    start = _base_time()
    events = []

    for index in range(20):
        events.extend(
            engine.process(
                _packet(
                    dst_port=1000 + index,
                    flags=set(),
                    timestamp=start + timedelta(milliseconds=index),
                )
            )
        )

    port_scan_events = [event for event in events if event.rule_name == "port_scan"]
    assert port_scan_events
    assert port_scan_events[-1].source_ip == "10.0.0.50"
    assert port_scan_events[-1].evidence["distinct_ports"] > 15
    assert "target_ports" in port_scan_events[-1].evidence
    assert len(port_scan_events[-1].evidence["target_ports"]) > 15
    assert port_scan_events[-1].evidence["target_port"] is not None
    assert set(port_scan_events[-1].evidence["target_ports"]) == set(range(1000, 1020))


def test_syn_flood_rule_triggers_on_syn_burst():
    engine = _engine_with_low_thresholds()
    start = _base_time()
    events = []

    for index in range(25):
        events.extend(
            engine.process(
                _packet(
                    dst_ip="10.0.0.99",
                    dst_port=80,
                    flags={"SYN"},
                    timestamp=start + timedelta(milliseconds=index),
                )
            )
        )

    syn_events = [event for event in events if event.rule_name == "syn_flood"]
    assert syn_events
    assert syn_events[-1].source_ip == "10.0.0.50"
    assert syn_events[-1].target_ip == "10.0.0.99"
    assert syn_events[-1].evidence["syn_count"] > 20
    assert syn_events[-1].evidence["target_port"] == 80


def test_ssh_bruteforce_rule_triggers_on_port_22_attempts():
    engine = _engine_with_low_thresholds()
    start = _base_time()
    events = []

    for index in range(15):
        events.extend(
            engine.process(
                _packet(
                    dst_ip="10.0.0.22",
                    dst_port=22,
                    flags={"SYN"},
                    timestamp=start + timedelta(milliseconds=index),
                )
            )
        )

    ssh_events = [event for event in events if event.rule_name == "ssh_bruteforce"]
    assert ssh_events
    assert ssh_events[-1].source_ip == "10.0.0.50"
    assert ssh_events[-1].target_ip == "10.0.0.22"
    assert ssh_events[-1].evidence["attempts"] > 10
    assert ssh_events[-1].evidence["target_port"] == 22
