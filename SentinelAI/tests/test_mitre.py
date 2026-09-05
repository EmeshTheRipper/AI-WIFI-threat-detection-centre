"""Tests for the MITRE ATT&CK mapping module."""

from src.detection import ThreatVerdict
from src.mitre import (
    RULE_TECHNIQUES,
    annotate_incident,
    annotate_verdict,
    describe,
    map_rule,
)


def _make_verdict(verdict="suspicious", rule_names=None):
    rule_names = rule_names if rule_names is not None else []
    return ThreatVerdict(
        src_ip="1.1.1.1",
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="TCP",
        rule_alert=bool(rule_names),
        rule_severity="high" if rule_names else None,
        rule_confidence=0.7 if rule_names else 0.0,
        ml_prediction="attack" if verdict == "malicious" else "normal",
        ml_confidence=0.8,
        verdict=verdict,
        combined_confidence=0.8,
        reasons=[],
        rule_names=rule_names,
    )


def test_rule_catalog_has_builtin_rules():
    assert "Port Scan" in RULE_TECHNIQUES
    assert "SYN Flood" in RULE_TECHNIQUES
    assert "Ping Sweep" in RULE_TECHNIQUES
    assert "ARP Spoofing" in RULE_TECHNIQUES


def test_map_rule_returns_technique():
    techniques = map_rule("Port Scan")
    assert len(techniques) == 1
    assert techniques[0].technique_id == "T1046"
    assert techniques[0].name == "Network Service Discovery"
    assert techniques[0].tactic == "Discovery"


def test_map_arp_spoofing_technique():
    techniques = map_rule("ARP Spoofing")
    assert len(techniques) == 1
    assert techniques[0].technique_id == "T1557.002"
    assert techniques[0].tactic == "Credential Access"


def test_map_unknown_rule_returns_empty():
    assert map_rule("Does Not Exist") == []


def test_annotate_verdict_port_scan():
    v = _make_verdict(verdict="suspicious", rule_names=["Port Scan"])
    ann = annotate_verdict(v)
    assert "T1046" in ann["technique_ids"]
    assert "Discovery" in ann["tactics"]


def test_annotate_verdict_syn_flood():
    v = _make_verdict(verdict="suspicious", rule_names=["SYN Flood"])
    ann = annotate_verdict(v)
    assert "T1498" in ann["technique_ids"]
    assert "Impact" in ann["tactics"]


def test_annotate_verdict_malicious_adds_technique():
    v = _make_verdict(verdict="malicious", rule_names=["Port Scan"])
    ann = annotate_verdict(v)
    assert "T1046" in ann["technique_ids"]
    assert "T1190" in ann["technique_ids"]


def test_annotate_incident_aggregates():
    verdicts = [
        _make_verdict(verdict="suspicious", rule_names=["Port Scan"]),
        _make_verdict(verdict="suspicious", rule_names=["Ping Sweep"]),
    ]
    inc = type("Inc", (), {"verdicts": verdicts})()
    ann = annotate_incident(inc)
    assert "T1046" in ann["technique_ids"]
    assert "T1018" in ann["technique_ids"]
    assert ann["tactic_count"] == 1  # both Discovery


def test_describe_output():
    v = _make_verdict(verdict="suspicious", rule_names=["Port Scan"])
    ann = annotate_verdict(v)
    text = describe(ann)
    assert "T1046" in text
    assert "Network Service Discovery" in text
