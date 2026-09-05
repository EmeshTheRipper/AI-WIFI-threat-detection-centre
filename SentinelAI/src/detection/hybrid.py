"""Hybrid detection engine combining rule-based and ML signals.

Merges per-IP rule alerts with per-flow ML predictions into a unified
verdict for each observed flow.
"""

import logging
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from src.features.builder import encode_features

from .alerts import SEVERITY_ORDER, ThreatAlert
from .engine import RuleEngine

logger = logging.getLogger(__name__)


@dataclass
class ThreatVerdict:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str

    rule_alert: bool
    rule_severity: str | None
    rule_confidence: float

    ml_prediction: str
    ml_confidence: float

    verdict: str
    combined_confidence: float
    reasons: list[str] = field(default_factory=list)
    rule_names: list[str] = field(default_factory=list)

    def summary(self) -> str:
        tag = {"normal": "OK", "suspicious": "???", "malicious": "!!!"}[self.verdict]
        return (
            f"[{tag:>3}] {self.src_ip}:{self.dst_port} -> {self.dst_ip} "
            f"({self.protocol}) verdict={self.verdict} "
            f"conf={self.combined_confidence:.0%} "
            f"reasons={self.reasons}"
        )


class HybridEngine:
    def __init__(
        self,
        rule_engine: RuleEngine | None = None,
        model_path: str | None = None,
        rule_weight: float = 0.5,
        ml_weight: float = 0.5,
    ):
        self.rule_engine = rule_engine or RuleEngine()
        self.model_path = model_path
        self.rule_weight = rule_weight
        self.ml_weight = ml_weight
        self._predictor = None

    def _get_predictor(self):
        if self._predictor is None and self.model_path:
            from src.ml.predictor import ModelPredictor
            self._predictor = ModelPredictor.from_model(self.model_path)
        return self._predictor

    def analyze(self, df: pd.DataFrame) -> list[ThreatVerdict]:
        rule_alerts = self.rule_engine.analyze(df)
        alert_map = self._build_alert_map(rule_alerts)
        rule_names_map = self._build_rule_names_map(rule_alerts)

        predictor = self._get_predictor()
        if predictor:
            df_encoded = encode_features(df, drop_ips=False)
            classified = predictor.classify(df_encoded)
        else:
            classified = df.copy()
            classified["prediction"] = 0
            classified["confidence"] = 0.0

        raw_proto = df["protocol"] if "protocol" in df.columns else pd.Series([""] * len(df), index=df.index)

        verdicts = []
        for idx, row in classified.iterrows():
            src_ip = str(row.get("src_ip", ""))
            rule_hit = alert_map.get(src_ip)

            rule_alert = rule_hit is not None
            rule_severity = rule_hit.severity if rule_hit else None
            rule_conf = rule_hit.confidence if rule_hit else 0.0

            ml_pred = "attack" if row.get("prediction", 0) == 1 else "normal"
            raw_ml_conf = row.get("confidence", 0.0)
            ml_conf = float(raw_ml_conf) if raw_ml_conf is not None else 0.0
            raw_dst_port = row.get("dst_port", 0)
            dst_port = int(raw_dst_port) if raw_dst_port is not None else 0

            verdict, combined_conf, reasons = self._combine(
                rule_alert, rule_severity, rule_conf,
                ml_pred, ml_conf,
            )

            verdicts.append(ThreatVerdict(
                src_ip=src_ip,
                dst_ip=str(row.get("dst_ip", "")),
                dst_port=dst_port,
                protocol=str(raw_proto.get(idx, "")),
                rule_alert=rule_alert,
                rule_severity=rule_severity,
                rule_confidence=rule_conf,
                ml_prediction=ml_pred,
                ml_confidence=ml_conf,
                verdict=verdict,
                combined_confidence=combined_conf,
                reasons=reasons,
                rule_names=list(rule_names_map.get(src_ip, [])),
            ))

        logger.info("Hybrid analysis complete: %d verdicts", len(verdicts))
        return verdicts

    def summary(self, verdicts: list[ThreatVerdict]) -> dict:
        by_verdict = {}
        for v in verdicts:
            by_verdict[v.verdict] = by_verdict.get(v.verdict, 0) + 1
        return {
            "total": len(verdicts),
            "by_verdict": by_verdict,
            "malicious_count": by_verdict.get("malicious", 0),
            "suspicious_count": by_verdict.get("suspicious", 0),
        }

    def _combine(
        self,
        rule_alert: bool,
        rule_severity: str | None,
        rule_conf: float,
        ml_pred: str,
        ml_conf: float,
    ) -> tuple[str, float, list[str]]:
        reasons = []

        if rule_alert:
            reasons.append(f"rule:{rule_severity}")
        if ml_pred == "attack":
            reasons.append(f"ml:attack({ml_conf:.0%})")

        if rule_alert and ml_pred == "attack":
            severity_score = SEVERITY_ORDER.get(rule_severity or "", 0) / 4
            combined = (self.rule_weight * severity_score) + (self.ml_weight * ml_conf)
            return "malicious", round(min(combined, 1.0), 3), reasons

        if rule_alert:
            return "suspicious", round(rule_conf, 3), reasons

        if ml_pred == "attack":
            return "suspicious", round(ml_conf, 3), reasons

        return "normal", round(max(ml_conf, 1 - rule_conf), 3), reasons

    def _build_alert_map(self, alerts: list[ThreatAlert]) -> dict[str, ThreatAlert]:
        best: dict[str, ThreatAlert] = {}
        for alert in alerts:
            existing = best.get(alert.src_ip)
            if existing is None or SEVERITY_ORDER[alert.severity] > SEVERITY_ORDER[existing.severity]:
                best[alert.src_ip] = alert
        return best

    def _build_rule_names_map(self, alerts: list[ThreatAlert]) -> dict[str, set]:
        names: dict[str, set] = {}
        for alert in alerts:
            names.setdefault(alert.src_ip, set()).add(alert.rule_name)
        return {k: v for k, v in names.items()}
