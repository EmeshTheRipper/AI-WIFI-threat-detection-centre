"""Tests for the event correlation module."""

import numpy as np

from src.correlation import Correlator, Incident
from src.detection import HybridEngine, RuleEngine, ThreatVerdict


def _make_verdict(
    src_ip="1.1.1.1",
    dst_ip="10.0.0.1",
    dst_port=80,
    protocol="TCP",
    verdict="suspicious",
    conf=0.8,
    rule_alert=False,
    ml_attack=False,
):
    return ThreatVerdict(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        rule_alert=rule_alert,
        rule_severity="high" if rule_alert else None,
        rule_confidence=0.7 if rule_alert else 0.0,
        ml_prediction="attack" if ml_attack else "normal",
        ml_confidence=conf if ml_attack else 0.0,
        verdict=verdict,
        combined_confidence=conf,
        reasons=[],
    )


def test_correlator_groups_by_source():
    verdicts = [
        _make_verdict(src_ip="1.1.1.1", dst_ip="10.0.0.1"),
        _make_verdict(src_ip="1.1.1.1", dst_ip="10.0.0.2"),
        _make_verdict(src_ip="2.2.2.2", dst_ip="10.0.0.1"),
    ]
    incidents = Correlator().correlate(verdicts)
    assert len(incidents) == 2
    by_src = {i.src_ip: i for i in incidents}
    assert by_src["1.1.1.1"].total_events == 2
    assert by_src["2.2.2.2"].total_events == 1


def test_correlator_excludes_normal_by_default():
    verdicts = [
        _make_verdict(verdict="normal", conf=0.2),
        _make_verdict(verdict="suspicious", conf=0.7),
    ]
    incidents = Correlator().correlate(verdicts)
    assert len(incidents) == 1
    assert incidents[0].total_events == 1


def test_correlator_include_normal():
    verdicts = [
        _make_verdict(src_ip="1.1.1.1", verdict="normal", conf=0.2),
        _make_verdict(src_ip="1.1.1.1", verdict="suspicious", conf=0.7),
    ]
    incidents = Correlator(min_confidence=0.0).correlate(verdicts, include_normal=True)
    assert len(incidents) == 1
    assert incidents[0].total_events == 2


def test_incident_properties():
    verdicts = [
        _make_verdict(dst_ip="10.0.0.1", dst_port=80, verdict="malicious", conf=0.9, rule_alert=True, ml_attack=True),
        _make_verdict(dst_ip="10.0.0.2", dst_port=443, verdict="suspicious", conf=0.6),
        _make_verdict(dst_ip="10.0.0.3", dst_port=8080, protocol="UDP", verdict="suspicious", conf=0.5),
    ]
    inc = Incident(src_ip="1.1.1.1", verdicts=verdicts)
    assert inc.malicious_events == 1
    assert inc.suspicious_events == 2
    assert inc.unique_targets == 3
    assert inc.unique_ports == 3
    assert inc.protocols == {"TCP", "UDP"}
    assert inc.had_rule_and_ml is True
    assert inc.max_confidence == 0.9


def test_critical_incidents_multi_target():
    verdicts = [
        _make_verdict(dst_ip=f"10.0.0.{i}", verdict="suspicious", conf=0.6)
        for i in range(1, 6)
    ]
    inc = Incident(src_ip="attacker", verdicts=verdicts)
    corr = Correlator(multi_target_min=3)
    critical = corr.critical_incidents([inc])
    assert inc in critical


def test_critical_incidents_threshold_not_met():
    verdicts = [_make_verdict(dst_ip="10.0.0.1", verdict="suspicious", conf=0.5)]
    inc = Incident(src_ip="attacker", verdicts=verdicts)
    corr = Correlator(multi_target_min=3)
    critical = corr.critical_incidents([inc])
    assert inc not in critical


def test_summary():
    verdicts = [
        _make_verdict(src_ip="1.1.1.1", dst_ip="10.0.0.1", verdict="suspicious", conf=0.6),
        _make_verdict(src_ip="1.1.1.1", dst_ip="10.0.0.2", verdict="suspicious", conf=0.6),
        _make_verdict(src_ip="1.1.1.1", dst_ip="10.0.0.3", verdict="suspicious", conf=0.6),
        _make_verdict(src_ip="1.1.1.1", dst_ip="10.0.0.4", verdict="suspicious", conf=0.6),
    ]
    corr = Correlator(multi_target_min=3)
    incidents = corr.correlate(verdicts)
    summary = corr.summary(incidents)
    assert summary["total_incidents"] == 1
    assert summary["critical_incidents"] == 1
    assert summary["critical_sources"] == ["1.1.1.1"]


def test_correlator_works_with_hybrid_engine():
    df = _make_port_scan_df()
    engine = HybridEngine(rule_engine=RuleEngine([]))
    verdicts = engine.analyze(df)
    corr = Correlator(min_confidence=0.0)
    incidents = corr.correlate(verdicts, include_normal=True)
    assert len(incidents) >= 1
    assert incidents[0].total_events >= 1


def _make_port_scan_df():
    records = []
    for port in range(80, 100):
        records.append({
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
        })
    from src.features import extract_flows, flows_to_dataframe
    return flows_to_dataframe(extract_flows(records))
