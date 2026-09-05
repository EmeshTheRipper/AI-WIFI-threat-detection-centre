"""Dashboard data pipeline.

Runs the full analysis chain (capture -> features -> hybrid -> correlation ->
risk -> MITRE) on a PCAP and returns plain-tabular data that a dashboard can
render, decoupled from any specific UI framework.
"""

import logging
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from src.capture import PcapReader, parse_packets
from src.correlation import Correlator
from src.detection import HybridEngine
from src.features import build_features_from_pcap, flow_summary
from src.mitre import annotate_incident
from src.risk import RiskScorer

logger = logging.getLogger(__name__)

MODEL_PATH = "models/sentinel_model.joblib"


@dataclass
class DashboardResult:
    pcap: str
    packets: int
    flows: int
    incidents: list
    scored: list
    summary: dict


def analyze(filepath: str) -> DashboardResult:
    packets = PcapReader(filepath).read_all()
    df_raw, fsummary = build_features_from_pcap(filepath, encode=False)

    model_path = MODEL_PATH if Path(MODEL_PATH).exists() else None
    engine = HybridEngine(model_path=model_path)
    verdicts = engine.analyze(df_raw)
    incidents = Correlator(min_confidence=0.0).correlate(verdicts, include_normal=True)

    scorer = RiskScorer()
    scored = scorer.score_all(incidents)

    return DashboardResult(
        pcap=filepath,
        packets=len(packets),
        flows=fsummary["flows"],
        incidents=incidents,
        scored=scored,
        summary=engine.summary(verdicts),
    )


def to_summary_frame(result: DashboardResult) -> pd.DataFrame:
    """One row per scored incident with risk level + MITRE info."""
    rows = []
    for s in result.scored:
        ann = annotate_incident(s.incident)
        rows.append({
            "src_ip": s.src_ip,
            "risk_score": s.score,
            "risk_level": s.level,
            "events": s.incident.total_events,
            "targets": s.incident.unique_targets,
            "confidence": round(s.incident.max_confidence, 3),
            "tactics": ", ".join(ann["tactics"]),
            "techniques": ", ".join(ann["technique_ids"]),
        })
    return pd.DataFrame(rows)


def level_distribution(result: DashboardResult) -> pd.DataFrame:
    """Count of incidents per risk level, ordered low -> critical."""
    order = ["minimal", "low", "medium", "high", "critical"]
    counts = {lv: 0 for lv in order}
    for s in result.scored:
        counts[s.level] += 1
    df = pd.DataFrame({"risk_level": list(counts.keys()), "count": list(counts.values())})
    return df.query("count > 0")
