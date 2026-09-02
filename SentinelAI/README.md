# SentinelAI

**Explainable AI-Based Hybrid Intrusion Detection and SOC Alert Correlation System**

SentinelAI is a cybersecurity platform that analyzes WiFi network traffic (PCAP files) and detects, scores, and explains threats through a layered pipeline:

- Rule-based detection (port scan, SYN flood, ping sweep)
- Machine-learning anomaly detection (RandomForest)
- Hybrid verdict engine (rules + ML)
- Event correlation by source host
- Weighted dynamic risk scoring (0-100)
- MITRE ATT&CK technique mapping
- Explainable AI (SHAP) for model predictions
- Interactive SOC Dashboard (Streamlit)

## Project Status

Complete — all 12 learning levels implemented and tested.

## Quick Start

```bash
# 1. Create virtual environment
python -m venv venv

# 2. Activate it (Windows)
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Train the ML model on synthetic data (creates models/sentinel_model.joblib)
python main.py --train
```

## Usage

### Analyze a PCAP (rules + ML hybrid detection through full pipeline)

```bash
python main.py data/samples/level2_sample.pcap
```

This prints capture info, feature summary, rule alerts, ML predictions,
hybrid verdicts, correlated incidents, risk scores, and MITRE ATT&CK mapping.

### Predict using the saved model

```bash
python main.py --predict data/samples/level2_sample.pcap
```

### ML explainability (SHAP global + local explanations)

```bash
python main.py --explain data/samples/level2_sample.pcap
```

### SOC Dashboard

```bash
python -m streamlit run dashboard/app.py
```

Opens an interactive dashboard with KPIs, risk-level distribution, scored
incident table, and MITRE summaries. Edit the PCAP path in the app to analyze
a different capture.

### Run tests

```bash
python -m pytest -v
```

## Detection Pipeline

```
PCAP capture ──> Feature extraction ──> Rule detection ─┐
                          │                             ├─> Hybrid verdicts
                          └─> ML classification ────────┘
                                   │
              Event correlation (by src IP) ──> Risk scoring (0-100)
                                   │
                    MITRE ATT&CK mapping + SHAP explainability
```

- **Features** (`src/features/`): group packets into flows, compute size/rate
  stats, one-hot encode protocol.
- **Rules** (`src/detection/rules.py`): `PortScanRule`, `SynFloodRule`, `PingSweepRule`.
- **Hybrid** (`src/detection/hybrid.py`): rules + ML → `malicious` / `suspicious` / `normal`.
- **Correlation** (`src/correlation/`): group flagged flows into per-source incidents.
- **Risk** (`src/risk/scorer.py`): weighted 0-100 score — confidence, volume,
  targets, severity, rule+ML agreement. Levels: minimal <20, low <40, medium
  <60, high <80, critical >=80.
- **MITRE** (`src/mitre/mappings.py`): maps Port Scan → T1046, SYN Flood →
  T1498, Ping Sweep → T1018, malicious → T1190.
- **Explainability** (`src/explainability/`): SHAP global feature importance +
  per-sample local explanations.
- **Dashboard** (`src/dashboard/` + `dashboard/app.py`): data pipeline + UI.

## Project Structure

```
SentinelAI/
├── src/
│   ├── capture/        # PCAP reading, packet parsing, sniffing
│   ├── features/       # Flow extraction + feature engineering
│   ├── detection/      # Rules, alerts, hybrid engine
│   ├── correlation/    # Incident correlation
│   ├── risk/           # Risk scoring
│   ├── mitre/          # ATT&CK mapping
│   ├── explainability/ # SHAP explanations
│   ├── ml/             # Dataset, trainer, predictor
│   └── dashboard/      # Dashboard data pipeline
├── dashboard/          # Streamlit app
├── data/               # Network data (PCAPs, CSVs)
├── models/             # Trained ML models
├── logs/               # Application logs
├── reports/            # Generated reports
├── tests/              # Test files (all levels)
├── main.py             # CLI entry point
├── pyproject.toml      # Pytest / project config
└── requirements.txt
```

## Notes

- The ML model is trained on **synthetic** data and is a placeholder for real
  labeled PCAP traffic. Until real labeled data is used, the ML component may
  flag benign sample traffic as suspicious.
- `models/sentinel_model.joblib` is gitignored; `models/sentinel_model.json`
  (model metadata) is tracked.

## License

MIT
