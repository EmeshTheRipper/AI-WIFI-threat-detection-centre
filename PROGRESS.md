# SentinelAI — Progress Tracker

> **How to use:** Check the level status below before continuing. Update this file whenever a level is started/completed. This file is the source of truth for where we left off so work can resume seamlessly after VS Code is closed.

## Current Status

- **Last updated:** 2026-09-02
- **Current level:** Level 7 — Event Correlation (NOT STARTED)
- **Last commit:** `f3e2452` — Level 6: hybrid detection
- **Branch:** `main` (pushed to GitHub)

## Learning Levels

| Level | Topic | Status |
|-------|-------|--------|
| 1 | Python & Project Fundamentals | ✅ DONE |
| 2 | Networking & PCAP Fundamentals | ✅ DONE |
| 3 | Data Processing & Feature Engineering | ✅ DONE |
| 4 | Rule-Based Threat Detection | ✅ DONE |
| 5 | Machine Learning Fundamentals | ✅ DONE |
| 6 | Hybrid Detection | ✅ DONE |
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

### Level 5 — Machine Learning Fundamentals (DONE)
- `src/ml/dataset.py` — Synthetic flow generator (normal/attack patterns) + CSV loader
- `src/ml/trainer.py` — `ModelTrainer` (RandomForest, train/eval/save/load, metrics)
- `src/ml/predictor.py` — `ModelPredictor` (load model, classify flows, summary)
- Tests: `tests/test_ml.py` (8 tests)
- NOTE: Trained on synthetic data; needs real labeled PCAP data for production use

### Level 6 — Hybrid Detection (DONE)
- `src/detection/hybrid.py` — `HybridEngine` (merges rule alerts + ML predictions per flow), `ThreatVerdict`
- Verdict logic: rule+ML both=attack → malicious; either one → suspicious; neither → normal
- Tests: `tests/test_hybrid.py` (8 tests)

## Environment / How to run

- **Python:** `py` launcher (Python 3.14.6). Installed deps: scapy, pandas, numpy, pytest, scikit-learn.
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

1. **Level 7 — Event Correlation:**
   - Correlate verdicts/incidents across time & sources to spot multi-step attacks.
   - Create `src/correlation/correlator.py`.
2. Install `shap` before Level 10 (Explainable AI).

## Scratch / decisions log

- 2026-09-02: Project scaffolded, git initialized, created root `.gitignore` (ignores `logs/`, `~$*`).
- 2026-09-02: Built Level 2 capture module (parser/reader/sniffer) + tests.
- 2026-09-02: Built Level 3 feature engineering module + tests. Fixed ICMP flows being dropped (fixed by allowing port-less ICMP flows).
- 2026-09-02: Built Level 4 rule-based detection module (PortScan, SYN Flood, Ping Sweep rules) + 7 tests. Rules use configurable thresholds, alerts sorted by severity. All 17 tests passing.
- 2026-09-02: Built Level 5 ML module (synthetic data generator, RandomForest trainer, predictor) + 8 tests. Installed scikit-learn. All 25 tests passing. Model saves/loads correctly. Synthetic data is a placeholder until real labeled captures are available.
- 2026-09-02: Built Level 6 hybrid detection (HybridEngine merging rules + ML into per-flow verdicts) + 8 tests. Fixed ML feature-alignment bug (missing one-hot proto columns). All 33 tests passing. Note: synthetic-trained ML flags sample PCAP as suspicious — expected until real labeled data.
