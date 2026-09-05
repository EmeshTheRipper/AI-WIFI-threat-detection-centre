# SentinelAI — Progress Tracker

> **How to use:** Check the level status below before continuing. Update this file whenever a level is started/completed. This file is the source of truth for where we left off so work can resume seamlessly after VS Code is closed.

## Current Status

- **Last updated:** 2026-09-06
- **Current level:** All 12 levels complete + Backend API, Database, Real-data training support, Docker deployment + **2026-09-06 hardening pass**
- **Last commit:** `e4deaaa` — feat(cli): add --live capture mode and pipeline consistency tests
- **Branch:** `main` (pushed to GitHub, 9 commits ahead on 2026-09-06)

## Learning Levels

| Level | Topic | Status |
|-------|-------|--------|
| 1 | Python & Project Fundamentals | ✅ DONE |
| 2 | Networking & PCAP Fundamentals | ✅ DONE |
| 3 | Data Processing & Feature Engineering | ✅ DONE |
| 4 | Rule-Based Threat Detection | ✅ DONE |
| 5 | Machine Learning Fundamentals | ✅ DONE |
| 6 | Hybrid Detection | ✅ DONE |
| 7 | Event Correlation | ✅ DONE |
| 8 | Risk Scoring | ✅ DONE |
| 9 | MITRE ATT&CK Mapping | ✅ DONE |
| 10 | Explainable AI | ✅ DONE |
| 11 | SOC Dashboard | ✅ DONE |
| 12 | Professional Engineering | ✅ DONE |

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

### Level 7 — Event Correlation (DONE)
- `src/correlation/correlator.py` — `Correlator`, `Incident`
- Groups flagged verdicts by src_ip into incidents; scores by events/targets/ports/protocols
- `critical_incidents()` flags multi-target, high-confidence, or high-volume attackers
- Tests: `tests/test_correlation.py` (8 tests)

### Level 8 — Risk Scoring (DONE)
- `src/risk/scorer.py` — `RiskScorer`, `ScoredIncident`, `risk_level()`
- Weighted 0-100 score: confidence, volume, targets, severity, rule+ML agreement
- Levels: minimal <20, low <40, medium <60, high <80, critical >=80
- Tests: `tests/test_risk.py` (8 tests)

### Level 9 — MITRE ATT&CK Mapping (DONE)
- `src/mitre/mappings.py` — `Technique`, per-rule technique catalog, `annotate_verdict`/`annotate_incident`/`describe`
- Port Scan → T1046 (Discovery), SYN Flood → T1498 (Impact), Ping Sweep → T1018 (Discovery), malicious → T1190
- Added `rule_names` to `ThreatVerdict` so verdicts carry the rules that fired
- Tests: `tests/test_mitre.py` (8 tests)

### Level 10 — Explainable AI (DONE)
- Installed `shap`.
- `src/explainability/explainer.py` — `Explainer` (global importance + per-sample local explanation + annotated dataframe), `__init__.py` export
- `python main.py --explain <file.pcap>` added
- Tests: `tests/test_explainability.py` (5 tests)

### Level 11 — SOC Dashboard (DONE)
- Installed `streamlit`.
- `src/dashboard/pipeline.py` — `analyze()`, `to_summary_frame()`, `level_distribution()` (reuses full analysis chain)
- `dashboard/app.py` — Streamlit app (KPIs, risk-level bar chart, scored-incident table, MITRE summary)
- Run: `SentinelAI\venv\Scripts\python.exe -m streamlit run dashboard/app.py`
- Tests: `tests/test_dashboard.py` (4 tests)

### Level 12 — Documentation & Deployment (DONE)
- Rewrote `README.md` with overview, quickstart, CLI + dashboard usage, full pipeline diagram, project structure, and notes.
- Finalized `requirements.txt`, `.gitignore`, `pyproject.toml`.
- Full test suite: 66 tests passing. Committed and pushed to GitHub.

### Extension — Backend API + Persistence + Deployment (DONE)
- Installed fastapi, uvicorn, sqlalchemy, python-dotenv, httpx.
- `src/db/database.py` — SQLAlchemy models (`Analysis`, `Incident`) + `Database` repository with SQLite persistence (`sentinelai.db`).
- `src/api/server.py` — FastAPI app: `/health`, `POST /analyze`, `GET /analyze/default`, `GET /incidents`, `GET /analyses`; interactive docs at `/docs`.
- `python main.py --api` starts the server on port 8000.
- Real-data training support: `label_encoded_features()` in `src/ml/dataset.py` (attach labels by list/scalar/src:dst:port dict) + `load_csv_dataset()`.
- Docker: `Dockerfile`, `docker-compose.yml` (port 8000 + healthcheck), `.dockerignore`.
- Tests: `tests/test_db.py` (3), `tests/test_api.py` (6), `tests/test_dataset_labels.py` (5).

### 2026-09-06 Hardening & Feature Pass (DONE)
- **Zero pyright/Pylance errors** across the entire codebase (src, main.py, dashboard, tests). Fixed ~81 type errors: pandas 3.0 native stubs (iterate with `reset_index().to_dict("records")`, guard `df["col"]` unions with `isinstance(x, pd.Series)`/`assert isinstance`, `cast(...)` for scalars), scapy submodule imports (`scapy.layers.l2`, `scapy.layers.inet`, `scapy.packet`, `scapy.utils`, `scapy.sendrecv`).
- **Enhanced inline documentation** (docstrings) across capture, features, detection, ml, db, explainability.
- **Live/PCAP pipeline consistency:** `parse_packet()` now emits a uniform schema with ARP/DNS fields; `extract_flows()` aggregates ARP flows; `tests/test_pipeline.py` proves the live-sniff path and PCAP-replay path converge on identical flow DataFrames.
- **ARP spoofing detection:** new `ArpSpoofRule` in `src/detection/rules.py` (conflicting MAC claims for one IP + high reply volume), registered in `RuleEngine.DEFAULT_RULES`; mapped to **MITRE T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning**.
- **Human-readable SHAP reasons:** `Explainer` now produces a plain-English `reason` on local explanations (`explain_dataframe` adds `reason` column).
- **`--live` CLI mode:** `python main.py --live [interface] [count]` snaps packets then runs the same hybrid engine + correlator + risk scoring + MITRE annotation as PCAP analysis.
- Full suite: **89 tests passing**, `pyright .` = 0 errors, 0 warnings. Pushed to GitHub.

## Environment / How to run

- **Python:** `py` launcher (Python 3.14.6). Installed deps: scapy, pandas, numpy, pytest, scikit-learn, shap, streamlit.
- **Venv:** exists at `SentinelAI/venv/` (activated via `SentinelAI\venv\Scripts\activate`).
- **Run app:** `SentinelAI\venv\Scripts\python.exe main.py data/samples/level2_sample.pcap`
- **Run dashboard:** `SentinelAI\venv\Scripts\python.exe -m streamlit run dashboard/app.py`
- **Run tests:** `SentinelAI\venv\Scripts\python.exe -m pytest -v`
- **NOTE:** shap, streamlit now installed. fastapi, sqlalchemy still in `requirements.txt` NOT installed.
- Sample data: `data/samples/level2_sample.pcap` (61 packets).

## Git notes

- Remote: `https://github.com/EmeshTheRipper/AI-WIFI-threat-detection-centre.git`
- Identity configured: `EmeshTheRipper <emesh.lamichhane123@gmail.com>`
- Git is on PATH only after the shell command `$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + ...` — in a fresh terminal run this, or reopen terminal after PATH refresh.

## Next actions (when resuming)

Done through the 2026-09-06 hardening pass. Ideas we did NOT do yet you can ask for:

- **Train on real labeled data** (CSV in `src/ml/dataset.py` `load_csv_dataset()` already supported) — replace synthetic-model caveats.
- **API hardening:** add auth (API key/JWT), switch SQLite → Postgres.
- **Dashboard v2:** add SHAP visualization tab (global importance bar + waterfall), historical DB views from `AnalyPeriod`/`Incident` tables, ARP-spoof incidents view.
- **More detections:** DNS tunneling rule, ICMP covert-channel rule, slow-scan/sparse scan detection, ARP reply flooding tuned for wireless.
- **Live mode polish:** interactive `--live` reporting, periodic flush, DB ingestion of live-incidents.
- **Packaging/CI:** `ruff`+`black` formatting, GitHub Actions run `pyright` + `pytest` on push, `Dockerfile` refactor to slim image.
- **Performance:** SHAP explainability cost for large PCAPs (already mitigated via `_shap` reuse), multiprocessing for flow extraction.

Any of these: just say "continue from PROGRESS.md and do X".

## Commands / files useful tomorrow

- Full status recap: on day #1 open PROGRESS.md. 
- Type check: `cd SentinelAI; venv\Scripts\pyright.exe .` (expect 0 errors)
- Tests: `cd SentinelAI; venv\Scripts\python.exe -m pytest -q` (expect 89 passed)

## Scratch / decisions log

- 2026-09-02: Project scaffolded, git initialized, created root `.gitignore` (ignores `logs/`, `~$*`).
- 2026-09-02: Built Level 2 capture module (parser/reader/sniffer) + tests.
- 2026-09-02: Built Level 3 feature engineering module + tests. Fixed ICMP flows being dropped (fixed by allowing port-less ICMP flows).
- 2026-09-02: Built Level 4 rule-based detection module (PortScan, SYN Flood, Ping Sweep rules) + 7 tests. Rules use configurable thresholds, alerts sorted by severity. All 17 tests passing.
- 2026-09-02: Built Level 5 ML module (synthetic data generator, RandomForest trainer, predictor) + 8 tests. Installed scikit-learn. All 25 tests passing. Model saves/loads correctly. Synthetic data is a placeholder until real labeled captures are available.
- 2026-09-02: Built Level 6 hybrid detection (HybridEngine merging rules + ML into per-flow verdicts) + 8 tests. Fixed ML feature-alignment bug (missing one-hot proto columns). All 33 tests passing. Note: synthetic-trained ML flags sample PCAP as suspicious — expected until real labeled data.
- 2026-09-02: Built Level 7 event correlation (Correlator grouping verdicts into per-source incidents, criticality heuristics) + 8 tests. All 41 tests passing. Output groups 51 incidents from sample PCAP, flags 10.0.0.2 as critical.
- 2026-09-02: Built Level 8 risk scoring (weighted 0-100 score + risk levels) + 8 tests. All 49 tests passing. Sample PCAP: 10.0.0.2 scored 45 (medium), rest low.
- 2026-09-02: Built Level 9 MITRE ATT&CK mapping (rule→technique catalog, verdict/incident annotation) + 8 tests. All 57 tests passing. Added rule_names to ThreatVerdict. Port-scan scenario maps to T1046+T1498.
- 2026-09-02: Built Level 10 Explainable AI (SHAP global importance + local explanations). Installed shap. All 62 tests passing. Added `--explain` CLI mode.
- 2026-09-02: Built Level 11 SOC Dashboard (Streamlit app + src/dashboard pipeline reusing full analysis chain). Installed streamlit. All 66 tests passing. `python -m streamlit run dashboard/app.py` launches successfully.
- 2026-09-02: Built Level 12 Documentation & Deployment (rewrote README.md, finalized requirements/gitignore/pyproject). All 12 levels complete. All 66 tests passing. Project complete.
- 2026-09-02: Built FastAPI backend (src/api), SQLAlchemy persistence (src/db), real-labeled-data training support (label_encoded_features), and Docker deployment (Dockerfile/docker-compose). Installed fastapi/uvicorn/sqlalchemy/httpx. Added `--api` CLI. All 80 tests passing.
- 2026-09-06: Updated .vscode settings (Pylance workspace/basic type checking), completed deps (joblib, httpx), fixed pandas/scapy typing across src+tests (0 pyright errors), documented modules, added ArpSpoofRule + MITRE T1557.002 mapping, SHAP human-readable reasons, `--live` CLI mode, and pipeline-consistency tests. All **89 tests** passing, repo pushed (9 commits: `52f7baa..e4deaaa`).
