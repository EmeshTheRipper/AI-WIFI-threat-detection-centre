"""Full analysis orchestration shared by the API and the web dashboard.

Runs the complete SentinelAI chain (capture -> features -> hybrid detection ->
correlation -> risk scoring -> MITRE mapping) over a set of parsed packet
records and produces a plain-JSON payload that the FastAPI backend and the
Streamlit UI both consume. Also persists every run into ``sentinelai.db`` so
analyses and incidents can be recalled later.
"""

import logging
from pathlib import Path

import pandas as pd

from src.capture import PcapReader, parse_packets
from src.correlation import Correlator
from src.detection import HybridEngine
from src.features import (
    encode_features,
    extract_flows,
    flow_summary,
    flows_to_dataframe,
)
from src.mitre import annotate_incident
from src.risk import RiskScorer

logger = logging.getLogger(__name__)

MODEL_PATH = "models/sentinel_model.joblib"


def build_features(records: list[dict]) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Convert parsed packet records into raw and encoded flow DataFrames.

    Args:
        records: Parsed packet records (list of dicts from ``parse_packets``).

    Returns:
        ``(raw_df, encoded_df, summary)`` where ``raw_df`` is the flow-level
        DataFrame used for rule/hybrid detection and ``encoded_df`` drops the
        raw IPs and one-hot encodes protocols for ML consumption. Rows in both
        DataFrames align 1:1 with the input records ordering.
    """
    flows = extract_flows(records)
    raw_df = flows_to_dataframe(flows)
    encoded_df = encode_features(raw_df, drop_ips=True)
    summary = flow_summary(raw_df)
    summary["raw_records"] = len(records)
    logger.info("Built %d flows from %d records", len(raw_df), len(records))
    return raw_df, encoded_df, summary


def _incident_rows(
    scored: list, analysis_id: int
) -> tuple[list[dict], list[dict]]:
    """Build DB rows and JSON payloads for scored incidents."""
    payloads: list[dict] = []
    db_rows: list[dict] = []
    for s in scored:
        category = _threat_category(s.incident)
        ann = annotate_incident(s.incident)
        tactics = ", ".join(ann["tactics"])
        techniques = ", ".join(ann["technique_ids"])
        payloads.append({
            "src_ip": s.src_ip,
            "threat_category": category,
            "risk_score": s.score,
            "risk_level": s.level,
            "events": s.incident.total_events,
            "targets": s.incident.unique_targets,
            "confidence": round(s.incident.max_confidence, 3),
            "tactics": tactics,
            "techniques": techniques,
        })
        db_rows.append({
            "analysis_id": analysis_id,
            "src_ip": s.src_ip,
            "risk_score": s.score,
            "risk_level": s.level,
            "events": s.incident.total_events,
            "targets": s.incident.unique_targets,
            "tactics": tactics,
            "techniques": techniques,
        })
    return payloads, db_rows


def _threat_category(incident) -> str:
    """Return a human-readable threat category for a correlated incident.

    Aggregates the rule signatures that fired for the source; falls back to
    ``Benign`` when nothing was flagged so the risk overview stays populated
    even for normal traffic.
    """
    names = sorted({
        name for v in incident.verdicts for name in v.rule_names
    })
    if names:
        return ", ".join(names)
    flagged = incident.suspicious_events + incident.malicious_events
    return "Benign" if flagged == 0 else "Suspicious"


def explain_flagged_flows(
    raw_df: pd.DataFrame,
    encoded_df: pd.DataFrame,
    verdicts: list,
    limit: int = 12,
) -> tuple[list[dict], bool]:
    """Produce SHAP reasons for flows that the hybrid engine flagged.

    Only runs when a trained model exists on disk, since SHAP needs the
    tree ensemble to extract tree-shape values.

    Returns:
        ``(explanations, model_available)`` where each explanation carries the
        source/target, prediction label, driving feature, and a plain-English
        ``reason`` string.
    """
    model_available = Path(MODEL_PATH).exists()
    flagged = [
        i for i, v in enumerate(verdicts)
        if v.verdict in {"suspicious", "malicious"}
    ]
    if not model_available:
        logger.warning("No model at %s — skipping SHAP explanations", MODEL_PATH)
        return [], False
    if not flagged:
        return [], True

    from src.explainability import Explainer
    from src.ml import ModelPredictor

    try:
        predictor = ModelPredictor.from_model(MODEL_PATH)
        model = predictor.trainer.model
    except Exception:  # pragma: no cover - corrupt model guard
        logger.exception("Could not load model for SHAP explanations")
        return [], False

    fitted = getattr(model, "feature_names_in_", None)
    columns = list(fitted) if fitted is not None else list(encoded_df.columns)
    X = encoded_df.filter(items=columns)
    explainer = Explainer(model)

    explanations: list[dict] = []
    for i in flagged[:limit]:
        row = raw_df.iloc[i]
        expl = explainer.local_explanation(X, row_index=i)
        driving = expl["driving_attack"]
        explanations.append({
            "src_ip": str(row.get("src_ip", "")),
            "dst_ip": str(row.get("dst_ip", "")),
            "protocol": str(row.get("protocol", "")),
            "label": expl["label_name"],
            "top_feature": driving[0]["feature"] if driving else "",
            "top_shap": driving[0]["shap"] if driving else 0.0,
            "reason": expl["reason"],
        })
    logger.info("Built %d SHAP explanations", len(explanations))
    return explanations, True


def run_full_analysis(
    records: list[dict],
    label: str,
    source: str,
    db=None,
    persist: bool = True,
    max_explanations: int = 12,
) -> dict:
    """Run the complete hybrid detection chain over parsed packet records.

    Args:
        records: Parsed packet records.
        label: Display name used to identify the run in the database.
        source: One of ``{"upload", "sample", "live"}``.
        db: Optional ``Database`` repository; required when ``persist``.
        persist: Whether to write the run into the database.
        max_explanations: Cap on SHAP explanations computed.

    Returns:
        A serializable dict with metrics, incident table rows, per-flow
        verdicts, and human-readable explanations.
    """
    packets = len(records)
    note = None
    if packets == 0:
        note = "No parseable packets captured. Live capture needs Npcap + admin rights (Windows) or root (Linux)."
        return _empty_result(label, source, note)

    raw_df, encoded_df, fsummary = build_features(records)

    model_path = MODEL_PATH if Path(MODEL_PATH).exists() else None
    engine = HybridEngine(model_path=model_path)
    verdicts = engine.analyze(raw_df)
    stats = engine.summary(verdicts)
    suspicious_alerts = int(stats["suspicious_count"] + stats["malicious_count"])

    incidents = Correlator(min_confidence=0.0).correlate(verdicts, include_normal=True)
    scored = RiskScorer().score_all(incidents)

    analysis_id = None
    if db is not None and persist:
        analysis_id = db.save_analysis(
            label, packets, int(fsummary["flows"]), len(scored)
        )

    incident_payloads, db_rows = _incident_rows(scored, analysis_id or 0)

    if db is not None and persist and db_rows:
        db.save_incidents(analysis_id or 0, db_rows)

    max_risk = max((s.score for s in scored), default=0.0)
    critical = sum(1 for s in scored if s.level == "critical")

    explanations, model_available = explain_flagged_flows(
        raw_df, encoded_df, verdicts, limit=max_explanations
    )

    flow_details = [
        {
            "src_ip": v.src_ip,
            "dst_ip": v.dst_ip,
            "dst_port": v.dst_port,
            "protocol": v.protocol,
            "verdict": v.verdict,
            "confidence": v.combined_confidence,
            "reasons": list(v.reasons),
            "rule_names": list(v.rule_names),
        }
        for v in verdicts
    ]

    return {
        "analysis_id": analysis_id,
        "pcap": label,
        "source": source,
        "note": note,
        "packets": packets,
        "flows": int(fsummary["flows"]),
        "verdict_counts": stats,
        "suspicious_alerts": suspicious_alerts,
        "total_incidents": len(scored),
        "critical_incidents": critical,
        "max_risk_score": max_risk,
        "incidents": incident_payloads,
        "flow_details": flow_details,
        "explanations": explanations,
        "model_available": model_available,
        "summary": {
            "flows": int(fsummary["flows"]),
            "protocol_counts": fsummary.get("protocol_counts", {}),
            "total_packets": fsummary.get("total_packets", 0),
            "total_bytes": fsummary.get("total_bytes", 0),
            "by_verdict": stats["by_verdict"],
        },
    }


def read_pcap_records(filepath: str) -> list[dict]:
    """Read and parse a PCAP file into packet records."""
    return parse_packets(PcapReader(filepath).read_all())


def capture_live_records(
    interface: str | None = None, count: int = 50, timeout: float = 20.0
) -> list[dict]:
    """Sniff packets from a live interface and parse them into records.

    Runs capture in a background thread (admin/root rights are required to
    open a raw socket) and returns whatever was parsed before the timeout.
    A permission error surfaces as an empty list plus a log line.

    Returns:
        Parsed packet records; may be empty when capture is unavailable.
    """
    import time

    from src.capture import PacketSniffer, parse_packet

    if count is None or count <= 0:
        count = 50

    records: list[dict] = []

    def collect(packet) -> None:
        record = parse_packet(packet)
        if record:
            records.append(record)

    try:
        sniffer = PacketSniffer(interface=interface, packet_count=count)
        sniffer.start(collect, count=count)
        deadline = time.time() + timeout
        while sniffer.is_running and time.time() < deadline:
            time.sleep(0.2)
        if sniffer.is_running:
            sniffer.stop()
    except Exception:  # pragma: no cover - permission/platform errors
        logger.exception("Live capture failed on interface %s", interface)

    logger.info("Live capture returned %d parsed packets", len(records))
    return records


def _empty_result(label: str, source: str, note: str) -> dict:
    """Return a zeroed result payload for runs with no parseable packets."""
    return {
        "analysis_id": None,
        "pcap": label,
        "source": source,
        "note": note,
        "packets": 0,
        "flows": 0,
        "verdict_counts": {
            "total": 0,
            "by_verdict": {},
            "malicious_count": 0,
            "suspicious_count": 0,
        },
        "suspicious_alerts": 0,
        "total_incidents": 0,
        "critical_incidents": 0,
        "max_risk_score": 0.0,
        "incidents": [],
        "flow_details": [],
        "explanations": [],
        "model_available": Path(MODEL_PATH).exists(),
        "summary": {
            "flows": 0,
            "protocol_counts": {},
            "total_packets": 0,
            "total_bytes": 0,
            "by_verdict": {},
        },
    }