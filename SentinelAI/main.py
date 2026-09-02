"""
SentinelAI - Explainable AI-Based Hybrid Intrusion Detection System

This is the main entry point for the application.
Run this file to start the system.
"""

import sys
import logging
from pathlib import Path

from src.capture import PcapReader, parse_packet, parse_packets
from src.detection import RuleEngine
from src.features import build_features_from_pcap, flow_summary


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


def analyze_pcap(filepath: str) -> int:
    """Read a PCAP file and print packet summaries."""
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
    df_encoded, summary = build_features_from_pcap(filepath)
    print(f"  Raw records parsed : {summary['raw_records']}")
    print(f"  Flows grouped      : {summary['flows']}")
    print(f"  Feature matrix     : {summary['shape'][0]} rows x {summary['shape'][1]} cols")

    df_raw, _ = build_features_from_pcap(filepath, encode=False)
    print(f"  Summary            : {flow_summary(df_raw)}")

    print("\n[DETECTION] Running rule-based threat detection...")
    engine = RuleEngine()
    alerts = engine.analyze(df_raw)
    stats = engine.summary(alerts)
    print(f"  Rules evaluated    : {len(engine.rules)}")
    print(f"  Alerts generated   : {stats['total']}")
    if stats["by_severity"]:
        print(f"  By severity        : {stats['by_severity']}")
    if stats["by_rule"]:
        print(f"  By rule            : {stats['by_rule']}")
    for alert in alerts:
        print(f"  {alert.summary()}")

    return len(records)


def main():
    """Main function - entry point of SentinelAI."""
    setup_logging()
    logger = logging.getLogger(__name__)

    logger.info("=" * 50)
    logger.info("SentinelAI Starting...")
    logger.info("=" * 50)

    print("\n[SENTINEL] SentinelAI - Threat Detection System")
    print("=" * 50)
    print("Level 4: Rule-Based Threat Detection loaded\n")

    if len(sys.argv) > 1:
        analyze_pcap(sys.argv[1])
    else:
        print("Usage: python main.py <path/to/file.pcap>")
        print("Offline PCAP analysis ready. Pass a PCAP file to analyze traffic.\n")


if __name__ == "__main__":
    main()
