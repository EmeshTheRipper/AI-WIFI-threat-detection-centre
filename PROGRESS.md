# SentinelAI — Progress Tracker

> **How to use:** Check the level status below before continuing. Update this file whenever a level is started/completed. This file is the source of truth for where we left off so work can resume seamlessly after VS Code is closed.

## Current Status

- **Last updated:** 2026-09-02
- **Current level:** Level 5 — Machine Learning Fundamentals (NOT STARTED)
- **Last commit:** `940bb0c` — Level 4: rule-based detection
- **Branch:** `main` (pushed to GitHub)

## Learning Levels

| Level | Topic | Status |
|-------|-------|--------|
| 1 | Python & Project Fundamentals | ✅ DONE |
| 2 | Networking & PCAP Fundamentals | ✅ DONE |
| 3 | Data Processing & Feature Engineering | ✅ DONE |
| 4 | Rule-Based Threat Detection | ✅ DONE |
| 5 | Machine Learning Fundamentals | ⬜ NOT STARTED |
| 6 | Hybrid Detection | ⬜ NOT STARTED |
| 7 | Event Correlation | ⬜ NOT STARTED |
| 8 | Risk Scoring | ⬜ NOT STARTED |
| 9 | MITRE ATT&CK Mapping | ⬜ NOT STARTED |
| 10 | Explainable AI | ⬜ NOT STARTED |
| 11 | SOC Dashboard | ⬜ NOT STARTED |
| 12 | Professional Engineering | ⬜ NOT STARTED |

## What's built so far

### Level 2 — Networking & PCAP Fundamentals (DONE)
- `src/capture/sniffer.py` — `PacketSniffer` (live capture, background thread)
- `src/capture/reader.py` — `PcapReader` (read/stream PCAP & PCAPng files)
- `src/capture/parser.py` — `parse_packet()` / `parse_packets()` (packet → structured dict)
- Tests: `tests/test_capture.py` (4 tests)

### Level 3 — Data Processing & Feature Engineering (DONE)
- `src/features/extractor.py` — `extract_flows()` (group packets by 5-tuple, compute flow stats)
- `src/features/builder.py` — `flows_to_dataframe()`, `encode_features()` (one-hot protocol), `flow_summary()`
- `src/features/dataset.py` — `build_features_from_pcap()` (full pipeline)
- Tests: `tests/test_features.py` (6 tests), `tests/fixtures.py`

### Level 4 — Rule-Based Threat Detection (DONE)
- `src/detection/alerts.py` — `ThreatAlert` dataclass (severity, confidence, evidence)
- `src/detection/rules.py` — `BaseRule` ABC + `PortScanRule`, `SynFloodRule`, `PingSweepRule`
- `src/detection/engine.py` — `RuleEngine` (applies rules, sorts by severity, summary stats)
- Tests: `tests/test_detection.py` (7 tests)

## Environment / How to run

- **Python:** `py` launcher (Python 3.14.6). Installed deps: scapy, pandas, numpy, pytest.
- **Venv:** exists at `SentinelAI/venv/` (activated via `SentinelAI\venv\Scripts\activate`).
- **Run app:** `SentinelAI\venv\Scripts\python.exe main.py data/samples/level2_sample.pcap`
- **Run tests:** `SentinelAI\venv\Scripts\python.exe -m pytest -v`
- **NOTE:** scikit-learn, shap, streamlit, fastapi, sqlalchemy etc. are in `requirements.txt` but **NOT installed yet** (needed starting Level 4/5).
- Sample data: `data/samples/level2_sample.pcap` (61 packets).

## Git notes

- Remote: `https://github.com/EmeshTheRipper/AI-WIFI-threat-detection-centre.git`
- Identity configured: `EmeshTheRipper <emesh.lamichhane123@gmail.com>`
- Git is on PATH only after the shell command `$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + ...` — in a fresh terminal run this, or reopen terminal after PATH refresh.

## Next actions (when resuming)

1. **Level 5 — Machine Learning Fundamentals:**
   - Install `scikit-learn` (`pip install scikit-learn`).
   - Create `src/ml/` module — train/test split, model training (Random Forest / SVM), evaluation metrics.
   - Integrate ML predictions with rule-based alerts.
2. Install `shap` before Level 10 (Explainable AI).

## Scratch / decisions log

- 2026-09-02: Project scaffolded, git initialized, created root `.gitignore` (ignores `logs/`, `~$*`).
- 2026-09-02: Built Level 2 capture module (parser/reader/sniffer) + tests.
- 2026-09-02: Built Level 3 feature engineering module + tests. Fixed ICMP flows being dropped (fixed by allowing port-less ICMP flows).
- 2026-09-02: Built Level 4 rule-based detection module (PortScan, SYN Flood, Ping Sweep rules) + 7 tests. Rules use configurable thresholds, alerts sorted by severity. All 17 tests passing.
