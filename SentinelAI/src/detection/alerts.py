"""Threat alert data structures for the detection module."""

from dataclasses import dataclass, field


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class ThreatAlert:
    rule_name: str
    severity: str
    confidence: float
    src_ip: str
    dst_ip: str | None
    description: str
    evidence: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"Invalid severity '{self.severity}', must be one of {list(SEVERITY_ORDER)}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be 0.0-1.0, got {self.confidence}")

    def summary(self) -> str:
        dst = self.dst_ip or "*"
        return (
            f"[{self.severity.upper():>8}] {self.rule_name}: "
            f"{self.src_ip} -> {dst} "
            f"(confidence={self.confidence:.0%}) {self.description}"
        )
