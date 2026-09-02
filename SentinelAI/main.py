"""
SentinelAI - Explainable AI-Based Hybrid Intrusion Detection System

This is the main entry point for the application.
Run this file to start the system.
"""

import sys
import logging
from pathlib import Path

from src.capture import PcapReader, parse_packet, parse_packets
from src.correlation import Correlator
from src.detection import HybridEngine, RuleEngine
from src.features import build_features_from_pcap, flow_summary
from src.mitre import annotate_incident, describe
from src.ml import ModelPredictor, ModelTrainer, generate_synthetic_flows
from src.risk import RiskScorer


def setup_logging():
    """Configure logging for the application."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        handlers=[
            logging.FileHandler("logs/sentinel.log"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def train_model():
    print("\n[ML] Training model on synthetic data...")
    df = generate_synthetic_flows(n_normal=500, n_attack=150)
    print(f"  Dataset: {len(df)} flows ({(df['label']==0).sum()} normal, {(df['label']==1).sum()} attack)")

    trainer = ModelTrainer()
    metrics = trainer.train(df)

    print(f"  Accuracy  : {metrics['accuracy']:.2%}")
    print(f"  Precision : {metrics['precision']:.2%}")
    print(f"  Recall    : {metrics['recall']:.2%}")
    print(f"  F1 Score  : {metrics['f1']:.2%}")

    model_path = "models/sentinel_model.joblib"
    trainer.save(model_path, metadata=metrics)
    print(f"\n  Model saved to {model_path}")


def predict_pcap(filepath: str):
    model_path = "models/sentinel_model.joblib"
    if not Path(model_path).exists():
        print(f"  No trained model found at {model_path}. Run --train first.")
        return

    print(f"\n[ML] Loading model from {model_path}...")
    predictor = ModelPredictor.from_model(model_path)

    print(f"[ML] Extracting features from {filepath}...")
    df, _ = build_features_from_pcap(filepath, encode=True)

    result = predictor.classify(df)
    summary = predictor.summary(result)

    print(f"  Total flows  : {summary['total']}")
    print(f"  Predictions  : {summary['counts']}")
    print(f"  Avg confidence: {summary['avg_confidence']:.2%}")

    attacks = result[result["prediction"] == 1]
    if not attacks.empty:
        print(f"\n  Suspicious flows ({len(attacks)}):")
        for _, row in attacks.head(10).iterrows():
            print(f"    confidence={row['confidence']:.0%} packets={int(row.get('packets', 0))}")


def analyze_pcap(filepath: str) -> int:
    """Read a PCAP file and run hybrid detection."""
    logger = logging.getLogger(__name__)
    logger.info("Analyzing PCAP: %s", filepath)

    reader = PcapReader(filepath)
    packets = reader.read_all()

    print(f"\n[CAPTURE] Loaded {len(packets)} packets from {filepath}")

    for pkt in packets[:10]:
        record = parse_packet(pkt)
        if record:
            print(
                f"  {record['protocol']:<5} {record['src_ip']}:{record['src_port']}"
                f" -> {record['dst_ip']}:{record['dst_port']} "
                f"({record['length']} bytes)"
            )

    records = parse_packets(packets)
    logger.info("Parsed %d/%d packets", len(records), len(packets))

    print("\n[FEATURES] Building flow features...")
    df_raw, summary = build_features_from_pcap(filepath, encode=False)
    print(f"  Flows grouped      : {summary['flows']}")
    print(f"  Summary            : {flow_summary(df_raw)}")

    print("\n[DETECTION] Running hybrid detection...")
    model_path = "models/sentinel_model.joblib"
    engine = HybridEngine(model_path=model_path if Path(model_path).exists() else None)
    verdicts = engine.analyze(df_raw)
    stats = engine.summary(verdicts)

    print(f"  Total verdicts     : {stats['total']}")
    print(f"  By verdict         : {stats['by_verdict']}")
    print()
    for v in verdicts:
        print(f"  {v.summary()}")

    print("\n[CORRELATION] Grouping events into incidents...")
    correlator = Correlator()
    incidents = correlator.correlate(verdicts)
    corr_summary = correlator.summary(incidents)
    print(f"  Total incidents    : {corr_summary['total_incidents']}")
    print(f"  Critical incidents : {corr_summary['critical_incidents']}")
    print()
    for inc in incidents:
        critical_mark = "  ** CRITICAL **" if inc in correlator.critical_incidents() else ""
        print(
            f"  {inc.src_ip:>16} : {inc.total_events} events "
            f"({inc.malicious_events} malicious / {inc.suspicious_events} susp), "
            f"{inc.unique_targets} targets, {inc.unique_ports} ports "
            f"protocols={sorted(inc.protocols)}{critical_mark}"
        )

    print("\n[RISK] Scoring incidents...")
    scorer = RiskScorer()
    scored = scorer.score_all(incidents)
    print(f"  Incidents scored   : {len(scored)}")
    print()
    for s in scored:
        print(f"  {s.summary()}  {s.components}")

    print("\n[MITRE] Mapping incidents to ATT&CK techniques...")
    for s in scored:
        ann = annotate_incident(s.incident)
        print(f"  {s.src_ip:>16} tactics={ann['tactics']} techniques={ann['technique_ids']}")
        if ann["technique_ids"]:
            print(f"       {describe(ann)}")

    return len(records)


def explain_model(filepath: str) -> None:
    """Run SHAP explanations on flows from a PCAP using the saved model."""
    model_path = "models/sentinel_model.joblib"
    if not Path(model_path).exists():
        print(f"  No trained model found at {model_path}. Run --train first.")
        return

    print(f"\n[XAI] Loading model from {model_path}...")
    predictor = ModelPredictor.from_model(model_path)
    model = predictor.trainer.model

    print(f"[XAI] Extracting features from {filepath}...")
    df, _ = build_features_from_pcap(filepath, encode=True)

    columns = list(model.feature_names_in_) if hasattr(model, "feature_names_in_") else list(df.columns)
    X = df[[c for c in df.columns if c in columns]]

    from src.explainability import Explainer

    explainer = Explainer(model)

    print("\n[XAI] Global feature importance (mean |SHAP|):")
    for i, row in enumerate(explainer.global_importance(X)):
        print(f"  {i + 1:>2}. {row['feature']:<18} {row['importance']:.4f}")

    print(f"\n[XAI] Local explanations for first {min(3, len(X))} flow(s):")
    for i in range(min(3, len(X))):
        expl = explainer.local_explanation(X, row_index=i)
        print(f"  Flow {i}: predicted {expl['label_name']} (prob-shift base {expl['base_value']})")
        for e in expl["driving_attack"]:
            print(f"     +{e['shap']:<8} {e['feature']} (val={e['value']})")


def main():
    """Main function - entry point of SentinelAI."""
    setup_logging()
    logger = logging.getLogger(__name__)

    logger.info("=" * 50)
    logger.info("SentinelAI Starting...")
    logger.info("=" * 50)

    print("\n[SENTINEL] SentinelAI - Threat Detection System")
    print("=" * 50)
    print("Hybrid IDS: rules + ML + correlation + risk + MITRE + XAI\n")

    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "--train":
            train_model()
        elif cmd == "--predict" and len(sys.argv) > 2:
            predict_pcap(sys.argv[2])
        elif cmd == "--explain" and len(sys.argv) > 2:
            explain_model(sys.argv[2])
        else:
            analyze_pcap(cmd)
    else:
        print("Usage:")
        print("  python main.py <file.pcap>           — Analyze PCAP (rules + ML)")
        print("  python main.py --train               — Train model on synthetic data")
        print("  python main.py --predict <file.pcap> — Predict using saved model")
        print("  python main.py --explain <file.pcap> — SHAP explanations on flows\n")


if __name__ == "__main__":
    main()
