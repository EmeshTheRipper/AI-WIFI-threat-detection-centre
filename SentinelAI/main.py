"""
SentinelAI - Explainable AI-Based Hybrid Intrusion Detection System

This is the main entry point for the application.
Run this file to start the system.
"""

import sys
import logging
from pathlib import Path


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


def main():
    """Main function - entry point of SentinelAI."""
    setup_logging()
    logger = logging.getLogger(__name__)

    logger.info("=" * 50)
    logger.info("SentinelAI Starting...")
    logger.info("=" * 50)

    print("\n[SENTINEL] SentinelAI - Threat Detection System")
    print("=" * 50)
    print("Status: Project structure created successfully!")
    print("Next step: Level 2 - Network & PCAP Fundamentals\n")


if __name__ == "__main__":
    main()
