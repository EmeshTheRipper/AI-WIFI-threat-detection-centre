"""Event correlation: group per-flow verdicts into attacker incidents.

Correlates suspicious/malicious verdicts by source IP to surface single
attackers and multi-stage campaigns, then scores and ranks the incidents.
"""

import logging
from dataclasses import dataclass, field
from typing import Iterable

logger = logging.getLogger(__name__)


@dataclass
class Incident:
    src_ip: str
    verdicts: list = field(default_factory=list)

    @property
    def total_events(self) -> int:
        return len(self.verdicts)

    @property
    def malicious_events(self) -> int:
        return sum(1 for v in self.verdicts if v.verdict == "malicious")

    @property
    def suspicious_events(self) -> int:
        return sum(1 for v in self.verdicts if v.verdict == "suspicious")

    @property
    def target_ips(self) -> set:
        return {v.dst_ip for v in self.verdicts if v.dst_ip}

    @property
    def unique_targets(self) -> int:
        return len(self.target_ips)

    @property
    def protocols(self) -> set:
        return {v.protocol for v in self.verdicts if v.protocol}

    @property
    def unique_ports(self) -> int:
        return len({v.dst_port for v in self.verdicts if v.dst_port})

    @property
    def max_confidence(self) -> float:
        return max((v.combined_confidence for v in self.verdicts), default=0.0)

    @property
    def had_rule_and_ml(self) -> bool:
        return any(v.rule_alert and v.ml_prediction == "attack" for v in self.verdicts)

    def evidence(self) -> dict:
        return {
            "total_events": self.total_events,
            "malicious_events": self.malicious_events,
            "suspicious_events": self.suspicious_events,
            "unique_targets": self.unique_targets,
            "unique_ports": self.unique_ports,
            "protocols": sorted(self.protocols),
            "max_confidence": round(self.max_confidence, 3),
            "had_rule_and_ml": self.had_rule_and_ml,
        }


class Correlator:
    def __init__(
        self,
        min_suspicious: int = 1,
        min_confidence: float = 0.5,
        multi_target_min: int = 3,
    ):
        self.min_suspicious = min_suspicious
        self.min_confidence = min_confidence
        self.multi_target_min = multi_target_min
        self._incidents: list[Incident] = []

    def correlate(
        self, verdicts: Iterable, include_normal: bool = False
    ) -> list[Incident]:
        flagged = []
        for v in verdicts:
            if v.verdict == "normal" and not include_normal:
                continue
            if v.combined_confidence < self.min_confidence:
                continue
            flagged.append(v)

        grouped: dict[str, list] = {}
        for v in flagged:
            grouped.setdefault(v.src_ip, []).append(v)

        self._incidents = [
            Incident(src_ip=src, verdicts=vs) for src, vs in grouped.items()
        ]
        self._incidents.sort(key=lambda i: -i.total_events)
        logger.info("Correlated %d incidents from %d flagged events", len(self._incidents), len(flagged))
        return self._incidents

    def critical_incidents(self, incidents: list[Incident] | None = None) -> list[Incident]:
        candidates = incidents if incidents is not None else self._incidents
        return [
            i for i in candidates
            if (
                i.malicious_events >= self.min_suspicious
                or i.suspicious_events >= max(self.min_suspicious * 2, 2)
                or i.unique_targets >= self.multi_target_min
                or (i.max_confidence >= 0.8 and i.total_events >= 2)
            )
        ]

    def summary(self, incidents: list[Incident] | None = None) -> dict:
        candidates = incidents if incidents is not None else self._incidents
        critical = self.critical_incidents(candidates)
        return {
            "total_incidents": len(candidates),
            "critical_incidents": len(critical),
            "total_events": sum(i.total_events for i in candidates),
            "critical_sources": [i.src_ip for i in critical],
        }
