"""Risk scoring for correlated incidents.

Assigns each incident a numeric risk score (0-100) by combining several
weighted factors: severity, confidence, event volume, target fan-out, and
signal agreement (rule AND ML). Provides human-readable risk levels.
"""

import logging
from dataclasses import dataclass, field
from typing import Iterable, Protocol

logger = logging.getLogger(__name__)

RISK_LEVELS = [
    ("critical", 80),
    ("high", 60),
    ("medium", 40),
    ("low", 20),
    ("minimal", 0),
]


class Scorable(Protocol):
    """Minimal interface the scorer needs from a correlated incident."""

    src_ip: str
    verdicts: list

    @property
    def total_events(self) -> int: ...

    @property
    def malicious_events(self) -> int: ...

    @property
    def suspicious_events(self) -> int: ...

    @property
    def unique_targets(self) -> int: ...

    @property
    def max_confidence(self) -> float: ...

    @property
    def had_rule_and_ml(self) -> bool: ...


def risk_level(score: float) -> str:
    """Map a 0-100 risk score to a named level."""
    for name, threshold in RISK_LEVELS:
        if score >= threshold:
            return name
    return "minimal"


@dataclass
class ScoredIncident:
    incident: Scorable
    score: float
    components: dict = field(default_factory=dict)

    @property
    def src_ip(self) -> str:
        return self.incident.src_ip

    @property
    def level(self) -> str:
        return risk_level(self.score)

    def summary(self) -> str:
        return (
            f"[{self.level.upper():>8}] {self.src_ip:>16} "
            f"risk={self.score:.0f}/100 "
            f"({self.incident.total_events} events, "
            f"{self.incident.unique_targets} targets)"
        )


class RiskScorer:
    def __init__(
        self,
        w_confidence: float = 0.35,
        w_volume: float = 0.20,
        w_targets: float = 0.20,
        w_severity: float = 0.15,
        w_agreement: float = 0.10,
    ):
        total = w_confidence + w_volume + w_targets + w_severity + w_agreement
        self.weights = {
            "confidence": w_confidence / total,
            "volume": w_volume / total,
            "targets": w_targets / total,
            "severity": w_severity / total,
            "agreement": w_agreement / total,
        }

    def score(self, incident: Scorable) -> ScoredIncident:
        components = {
            "confidence": self._confidence_score(incident),
            "volume": self._volume_score(incident),
            "targets": self._targets_score(incident),
            "severity": self._severity_score(incident),
            "agreement": self._agreement_score(incident),
        }

        score = sum(components[k] * self.weights[k] for k in components)
        score = max(0.0, min(100.0, score))

        logger.info(
            "Scored incident %s -> %.1f (%s)",
            incident.src_ip, score, risk_level(score),
        )
        return ScoredIncident(
            incident=incident,
            score=round(score, 1),
            components={k: round(v, 3) for k, v in components.items()},
        )

    def score_all(self, incidents: Iterable[Scorable]) -> list[ScoredIncident]:
        scored = [self.score(i) for i in incidents]
        scored.sort(key=lambda s: -s.score)
        return scored

    def _confidence_score(self, incident: Scorable) -> float:
        return min(incident.max_confidence * 100.0, 100.0)

    def _volume_score(self, incident: Scorable) -> float:
        events = incident.total_events
        if events >= 50:
            return 100.0
        return (events / 50.0) * 100.0

    def _targets_score(self, incident: Scorable) -> float:
        targets = incident.unique_targets
        if targets >= 20:
            return 100.0
        return (targets / 20.0) * 100.0

    def _severity_score(self, incident: Scorable) -> float:
        worst = 0
        for v in incident.verdicts:
            if v.rule_severity:
                sev = {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(v.rule_severity, 0)
                worst = max(worst, sev)
        if incident.had_rule_and_ml:
            worst = max(worst, 4)
        return (worst / 4.0) * 100.0

    def _agreement_score(self, incident: Scorable) -> float:
        if incident.had_rule_and_ml:
            return 100.0
        if incident.malicious_events > 0:
            return 70.0
        if incident.suspicious_events > 0:
            return 40.0
        return 0.0
