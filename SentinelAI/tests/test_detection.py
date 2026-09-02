"""Tests for the rule-based detection module."""

import pandas as pd

from src.detection import (
    SEVERITY_ORDER,
    PingSweepRule,
    PortScanRule,
    RuleEngine,
    SynFloodRule,
    ThreatAlert,
)
from src.features import extract_flows, flows_to_dataframe


def _make_df(records):
    flows = extract_flows(records)
    return flows_to_dataframe(flows)


def test_port_scan_detected():
    records = []
    for port in range(80, 100):
        records.append(
            {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "protocol": "TCP",
                "src_ip": "192.168.1.10",
                "dst_ip": "10.0.0.1",
                "src_port": 5555,
                "dst_port": port,
                "length": 60,
                "flags": "S",
                "payload_size": 0,
                "payload_sample": None,
            }
        )
    df = _make_df(records)
    rule = PortScanRule(min_unique_ports=5)
    alerts = rule.evaluate(df)
    assert len(alerts) >= 1
    assert alerts[0].rule_name == "Port Scan"
    assert alerts[0].src_ip == "192.168.1.10"


def test_syn_flood_detected():
    records = []
    for _ in range(30):
        records.append(
            {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "protocol": "TCP",
                "src_ip": "10.0.0.99",
                "dst_ip": "10.0.0.1",
                "src_port": 12345,
                "dst_port": 80,
                "length": 60,
                "flags": "S",
                "payload_size": 0,
                "payload_sample": None,
            }
        )
    df = _make_df(records)
    rule = SynFloodRule(min_syn_count=10, min_syn_ratio=0.5)
    alerts = rule.evaluate(df)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "SYN Flood"
    assert alerts[0].severity == "critical"
    assert alerts[0].src_ip == "10.0.0.99"


def test_ping_sweep_detected():
    records = []
    for host in range(1, 10):
        records.append(
            {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "protocol": "ICMP",
                "src_ip": "192.168.1.50",
                "dst_ip": f"10.0.0.{host}",
                "src_port": None,
                "dst_port": None,
                "length": 28,
                "flags": "type=8 code=0",
                "payload_size": 0,
                "payload_sample": None,
            }
        )
    df = _make_df(records)
    rule = PingSweepRule(min_unique_hosts=3)
    alerts = rule.evaluate(df)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "Ping Sweep"
    assert alerts[0].src_ip == "192.168.1.50"


def test_no_alerts_on_benign_traffic():
    records = [
        {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "protocol": "TCP",
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_port": 443,
            "length": 60,
            "flags": "SA",
            "payload_size": 100,
            "payload_sample": "aa",
        },
        {
            "timestamp": "2026-01-01T00:00:01+00:00",
            "protocol": "TCP",
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_port": 443,
            "length": 1500,
            "flags": "A",
            "payload_size": 1400,
            "payload_sample": "bb",
        },
    ]
    df = _make_df(records)
    engine = RuleEngine()
    alerts = engine.analyze(df)
    assert len(alerts) == 0


def test_engine_combines_rules():
    records = []
    for port in range(80, 100):
        records.append(
            {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "protocol": "TCP",
                "src_ip": "192.168.1.10",
                "dst_ip": "10.0.0.1",
                "src_port": 5555,
                "dst_port": port,
                "length": 60,
                "flags": "S",
                "payload_size": 0,
                "payload_sample": None,
            }
        )
    for _ in range(25):
        records.append(
            {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "protocol": "TCP",
                "src_ip": "10.0.0.99",
                "dst_ip": "10.0.0.1",
                "src_port": 12345,
                "dst_port": 80,
                "length": 60,
                "flags": "S",
                "payload_size": 0,
                "payload_sample": None,
            }
        )
    df = _make_df(records)
    engine = RuleEngine()
    alerts = engine.analyze(df)
    rule_names = {a.rule_name for a in alerts}
    assert "Port Scan" in rule_names
    assert "SYN Flood" in rule_names


def test_alert_severity_ordering():
    alerts = [
        ThreatAlert("Rule", "low", 0.5, "1.1.1.1", None, "low alert"),
        ThreatAlert("Rule", "critical", 0.9, "2.2.2.2", None, "crit alert"),
        ThreatAlert("Rule", "medium", 0.6, "3.3.3.3", None, "med alert"),
    ]
    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.severity, 0), reverse=True)
    assert [a.severity for a in alerts] == ["critical", "medium", "low"]


def test_custom_thresholds():
    records = []
    for port in range(80, 90):
        records.append(
            {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "protocol": "TCP",
                "src_ip": "192.168.1.10",
                "dst_ip": "10.0.0.1",
                "src_port": 5555,
                "dst_port": port,
                "length": 60,
                "flags": "S",
                "payload_size": 0,
                "payload_sample": None,
            }
        )
    df = _make_df(records)
    strict_rule = PortScanRule(min_unique_ports=100)
    lenient_rule = PortScanRule(min_unique_ports=2)
    strict_alerts = strict_rule.evaluate(df)
    lenient_alerts = lenient_rule.evaluate(df)
    assert len(strict_alerts) == 0
    assert len(lenient_alerts) >= 1
