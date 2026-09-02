"""Tests for the risk scoring module."""

from src.correlation import Incident
from src.detection import ThreatVerdict
from src.risk import RiskScorer, risk_level, ScoredIncident


def _make_verdict(
    verdict="suspicious",
    conf=0.8,
    rule_alert=False,
    rule_severity=None,
    ml_attack=False,
    dst_ip="10.0.0.1",
    dst_port=80,
    protocol="TCP",
):
    if ml_attack:
        verdict = "malicious"
    return ThreatVerdict(
        src_ip="1.1.1.1",
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        rule_alert=rule_alert,
        rule_severity=rule_severity if rule_alert else None,
        rule_confidence=0.7 if rule_alert else 0.0,
        ml_prediction="attack" if ml_attack else "normal",
        ml_confidence=conf if ml_attack else 0.0,
        verdict=verdict,
        combined_confidence=conf,
        reasons=[],
    )


def test_risk_level_boundaries():
    assert risk_level(85) == "critical"
    assert risk_level(70) == "high"
    assert risk_level(50) == "medium"
    assert risk_level(30) == "low"
    assert risk_level(10) == "minimal"


def test_score_single_low_risk():
    inc = Incident(src_ip="1.1.1.1", verdicts=[_make_verdict(conf=0.5)])
    scorer = RiskScorer()
    result = scorer.score(inc)
    assert result.score < 60
    assert "confidence" in result.components
    assert result.incident is inc


def test_score_high_risk_multi_target():
    verdicts = [
        _make_verdict(dst_ip=f"10.0.0.{i}", conf=0.9, rule_alert=True, rule_severity="critical", ml_attack=True, verdict="malicious")
        for i in range(1, 25)
    ]
    inc = Incident(src_ip="attacker", verdicts=verdicts)
    scorer = RiskScorer()
    result = scorer.score(inc)
    assert result.score >= 80
    assert result.level == "critical"


def test_scores_bounded_0_100():
    inc_min = Incident(src_ip="a", verdicts=[_make_verdict(verdict="normal", conf=0.0)])
    inc_max = Incident(
        src_ip="b",
        verdicts=[
            _make_verdict(conf=1.0, rule_alert=True, rule_severity="critical", ml_attack=True, verdict="malicious")
            for _ in range(100)
        ],
    )
    scorer = RiskScorer()
    hi = scorer.score(inc_max)
    assert hi.score <= 100.0
    assert 0.0 <= hi.score


def test_score_all_sorted_descending():
    inc_small = Incident(src_ip="small", verdicts=[_make_verdict(conf=0.4)])
    inc_big = Incident(
        src_ip="big",
        verdicts=[_make_verdict(conf=0.9, rule_alert=True, rule_severity="high", ml_attack=True, verdict="malicious")],
    )
    scored = RiskScorer().score_all([inc_small, inc_big])
    assert scored[0].src_ip == "big"
    assert scored[0].score >= scored[1].score


def test_custom_weights_change_score():
    inc = Incident(
        src_ip="x",
        verdicts=[_make_verdict(conf=0.9, rule_alert=True, rule_severity="critical", ml_attack=True, verdict="malicious")],
    )
    default = RiskScorer().score(inc)
    confidence_heavy = RiskScorer(w_confidence=0.8, w_volume=0.05, w_targets=0.05, w_severity=0.05, w_agreement=0.05).score(inc)
    assert default.score != confidence_heavy.score


def test_summary_string():
    inc = Incident(src_ip="1.1.1.1", verdicts=[_make_verdict(conf=0.9, rule_alert=True, rule_severity="critical", ml_attack=True, verdict="malicious")])
    result = RiskScorer().score(inc)
    s = result.summary()
    assert "1.1.1.1" in s
    assert "risk=" in s
    assert "events" in s


def test_agreement_adds_risk():
    solo = Incident(src_ip="a", verdicts=[_make_verdict(conf=0.9)])
    agreed = Incident(
        src_ip="b",
        verdicts=[_make_verdict(conf=0.9, rule_alert=True, rule_severity="medium", ml_attack=True, verdict="malicious")],
    )
    scorer = RiskScorer()
    score_solo = scorer.score(solo)
    score_agreed = scorer.score(agreed)
    assert score_agreed.score >= score_solo.score
