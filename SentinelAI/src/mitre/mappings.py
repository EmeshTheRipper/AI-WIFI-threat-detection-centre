"""MITRE ATT&CK technique mapping.

Maps detected rule/behavior signals to MITRE ATT&CK techniques and
tactics so verdicts and incidents can be annotated with industry-standard
adversary knowledge.
"""

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str
    description: str


# Map each built-in rule name to one or more ATT&CK techniques.
RULE_TECHNIQUES: dict[str, list[Technique]] = {
    "Port Scan": [
        Technique(
            technique_id="T1046",
            name="Network Service Discovery",
            tactic="Discovery",
            description="Scanning a range of ports to identify services running on a host.",
        ),
    ],
    "SYN Flood": [
        Technique(
            technique_id="T1498",
            name="Network Denial of Service",
            tactic="Impact",
            description="Overwhelming a service with incomplete TCP handshakes (SYN flood).",
        ),
    ],
    "Ping Sweep": [
        Technique(
            technique_id="T1018",
            name="Remote System Discovery",
            tactic="Discovery",
            description="Pinging a range of IPs to map live hosts on a network.",
        ),
    ],
}

# Behavior signals observed by ML (by verdict) mapped to techniques.
SIGNAL_TECHNIQUES: dict[str, list[Technique]] = {
    "malicious": [
        Technique(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            tactic="Initial Access",
            description="Confirmed malicious flow exploiting or abusing a public-facing service.",
        ),
    ],
}


def map_rule(rule_name: str) -> list[Technique]:
    """Return the ATT&CK techniques for a rule name."""
    return list(RULE_TECHNIQUES.get(rule_name, []))


def annotate_verdict(verdict) -> dict:
    """Return an annotation dict of ATT&CK techniques for a verdict."""
    techniques: dict[str, Technique] = {}

    rule_names = getattr(verdict, "rule_names", None) or []
    for rule_name in rule_names:
        for t in RULE_TECHNIQUES.get(rule_name, []):
            techniques[t.technique_id] = t

    if verdict.verdict == "malicious":
        for t in SIGNAL_TECHNIQUES.get("malicious", []):
            techniques[t.technique_id] = t

    return {
        "techniques": sorted(techniques.values(), key=lambda t: t.technique_id),
        "tactics": sorted({t.tactic for t in techniques.values()}),
        "technique_ids": sorted(techniques.keys()),
    }


def annotate_incident(incident) -> dict:
    """Aggregate ATT&CK annotations across an incident's verdicts."""
    techniques: dict[str, Technique] = {}
    for v in incident.verdicts:
        ann = annotate_verdict(v)
        for t in ann["techniques"]:
            techniques[t.technique_id] = t
    return {
        "techniques": sorted(techniques.values(), key=lambda t: t.technique_id),
        "tactics": sorted({t.tactic for t in techniques.values()}),
        "technique_ids": sorted(techniques.keys()),
        "tactic_count": len({t.tactic for t in techniques.values()}),
    }


def describe(annotation: dict) -> str:
    """Human-readable summary of an annotation dict."""
    if not annotation["technique_ids"]:
        return "No ATT&CK techniques mapped"
    parts = []
    for t in annotation["techniques"]:
        parts.append(f"{t.technique_id} ({t.name}, {t.tactic}): {t.description}")
    return " | ".join(parts)
