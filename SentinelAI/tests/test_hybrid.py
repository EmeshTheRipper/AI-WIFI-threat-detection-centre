"""Tests for the hybrid detection engine."""

import numpy as np
import pandas as pd

from src.detection import HybridEngine, RuleEngine, ThreatVerdict
from src.ml.dataset import generate_synthetic_flows
from src.ml.trainer import ModelTrainer


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


def _make_syn_flood_df():
    records = []
    for _ in range(30):
        records.append({
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
        })
    from src.features import extract_flows, flows_to_dataframe
    return flows_to_dataframe(extract_flows(records))


def _make_benign_df():
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
    ]
    from src.features import extract_flows, flows_to_dataframe
    return flows_to_dataframe(extract_flows(records))


def test_hybrid_rules_only():
    df = _make_port_scan_df()
    engine = HybridEngine()
    verdicts = engine.analyze(df)
    assert len(verdicts) == 20  # 20 flows, one per port
    for v in verdicts:
        assert v.rule_alert is True
        assert v.verdict == "suspicious"  # rule-only, no ML -> suspicious
        assert any(r.startswith("rule:") for r in v.reasons)


def test_hybrid_ml_only(tmp_path):
    df_syn = generate_synthetic_flows(n_normal=100, n_attack=50, seed=42)
    trainer = ModelTrainer()
    trainer.train(df_syn)
    model_path = str(tmp_path / "test_model.joblib")
    trainer.save(model_path)

    benign_df = _make_benign_df()
    engine = HybridEngine(rule_engine=RuleEngine([]), model_path=model_path)
    verdicts = engine.analyze(benign_df)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.rule_alert is False
    assert v.verdict in ("normal", "suspicious")


def test_hybrid_both_signals(tmp_path):
    df_syn = generate_synthetic_flows(n_normal=100, n_attack=50, seed=42)
    trainer = ModelTrainer()
    trainer.train(df_syn)
    model_path = str(tmp_path / "test_model.joblib")
    trainer.save(model_path)

    df = _make_syn_flood_df()
    engine = HybridEngine(model_path=model_path)
    verdicts = engine.analyze(df)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.rule_alert is True
    assert v.ml_prediction == "attack"
    assert v.verdict == "malicious"
    assert "rule:critical" in v.reasons
    assert any("ml:attack" in r for r in v.reasons)


def test_hybrid_no_model_falls_back_to_rules():
    df = _make_port_scan_df()
    engine = HybridEngine(model_path=None)
    verdicts = engine.analyze(df)
    assert len(verdicts) == 20  # 20 flows
    for v in verdicts:
        assert v.rule_alert is True
        assert v.ml_prediction == "normal"
        assert v.verdict == "suspicious"


def test_hybrid_verdict_normal():
    df = _make_benign_df()
    engine = HybridEngine(rule_engine=RuleEngine([]))
    verdicts = engine.analyze(df)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.verdict == "normal"
    assert v.rule_alert is False
    assert v.ml_prediction == "normal"


def test_hybrid_summary():
    df = _make_port_scan_df()
    engine = HybridEngine()
    verdicts = engine.analyze(df)
    summary = engine.summary(verdicts)
    assert "total" in summary
    assert "by_verdict" in summary
    assert summary["total"] == 20


def test_hybrid_custom_weights(tmp_path):
    df_syn = generate_synthetic_flows(n_normal=100, n_attack=50, seed=42)
    trainer = ModelTrainer()
    trainer.train(df_syn)
    model_path = str(tmp_path / "test_model.joblib")
    trainer.save(model_path)

    df = _make_syn_flood_df()
    engine_low_rule = HybridEngine(model_path=model_path, rule_weight=0.2, ml_weight=0.8)
    engine_high_rule = HybridEngine(model_path=model_path, rule_weight=0.8, ml_weight=0.2)
    v_low = engine_low_rule.analyze(df)[0]
    v_high = engine_high_rule.analyze(df)[0]
    assert v_low.combined_confidence != v_high.combined_confidence


def test_verdict_summary_format():
    v = ThreatVerdict(
        src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP",
        rule_alert=True, rule_severity="high", rule_confidence=0.8,
        ml_prediction="attack", ml_confidence=0.9,
        verdict="malicious", combined_confidence=0.85,
        reasons=["rule:high", "ml:attack(90%)"],
    )
    s = v.summary()
    assert "malicious" in s
    assert "1.1.1.1" in s
