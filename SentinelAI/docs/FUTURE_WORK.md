# SentinelAI — Future Work & Ideas

This file captures optional next steps and ideas. All 12 learning levels are
complete and the backend (FastAPI + SQLAlchemy) and Docker deployment are
built. Everything below is **optional** — pick up where you left off.

**Last updated:** 2026-09-02
**Project state:** v1.1.0 tagged and pushed to GitHub.

---

## 1. Train on Real Labeled Data (highest priority)

The ML model is currently trained on **synthetic** data and over-flags benign
traffic (the sample PCAP is classified fully "suspicious"). For production it
should be retrained on real labeled flows.

### How
1. Put labeled flow CSVs in `data/datasets/` (columns = feature columns +
   a `label` column: 0 = normal, 1 = attack).
2. Retrain:
   ```python
   from src.ml.dataset import load_csv_dataset
   from src.ml.trainer import ModelTrainer

   df = load_csv_dataset("data/datasets/my_labeled.csv")
   trainer = ModelTrainer()
   trainer.train(df)
   trainer.save("models/sentinel_model.joblib", metadata={"source": "real-labeled"})
   ```
3. For per-flow labels over PCAP-derived features, use
   `label_encoded_features(features_df, labels)` in `src/ml/dataset.py`
   (labels can be a list, a scalar, or a dict keyed by `src_ip:dst_ip:dst_port`).

### Sources of labeled network datasets (research these)
- **UNSW-NB15**, **CICIDS2017**, **Kyoto 2006+**, **CIC-IDS2017**
- Campus / home WiFi captures (less ready-made labeling; needs manual labeling)

---

## 2. Backend / API Enhancements

- **Authentication:** add JWT / API-key auth to the FastAPI endpoints.
- **Real database:** switch from SQLite to PostgreSQL (env-configured URL via
  `DATABASE_URL` + `python-dotenv`).
- **Async endpoints:** convert the CPU-bound `/analyze` to a background task /
  job queue so large PCAPs don't block the request.
- **More endpoints:** `POST /predict` (predict on an uploaded flow), `GET
  /mitre-catalog`, `GET /model-feature-importance` (tie in SHAP).
- **Rate limiting + CORS** for a public-facing deployment.

---

## 3. Dashboard (Streamlit) Enhancements

- **Live capture view:** stream packets/capture into the dashboard using
  `src/capture/sniffer.py`.
- **Historical view:** read incidents from the SQLite/Postgres DB (via the
  API) instead of only analyzing a fresh PCAP.
- **SHAP visualizations:** waterfall / bar plots per prediction directly in
  the dashboard.
- **MITRE filtering:** filter the incident table by tactic/technique.

---

## 4. Detection / ML Improvements

- **More rules + MITRE mappings:** e.g. Brute force / repeated auth failures
  → T1110, ARP spoofing → T1557, DNS tunneling → T1572.
- **More ML features:** time-windowed rates, packet inter-arrival stats,
  byte-ratio features, TTL variance, TCP flag distributions.
- **Feature-importance monitoring:** wire `Explainer.global_importance()` into
  a drift check when new models are trained.
- **Ensemble / threshold tuning:** add precision-recall trade-off control in
  `HybridEngine._combine` and expose it in the CLI.

---

## 5. Deployment

- **Cloud:** deploy the FastAPI + dashboard to a host (Render, Railway,
  Fly.io, or a VPS).
- **CI/CD:** GitHub Actions workflow to run `pytest` on push + auto-build the
  Docker image.
- **Logging/observability:** ship `logs/` to a central store; add request
  tracing to the API.
- **Model registry:** version trained models and store metadata in the DB
  (currently only JSON sidecar `models/sentinel_model.json`).

---

## 6. Miscellaneous / Quality

- **PCAPng support** already handled by `PcapReader`; add tests with real
  pcapng fixtures.
- **Packaging:** add `__main__` entry so `python -m sentinelai` works, make it
  an installable package (`pip install -e .`).
- **More docs:** architecture diagram (Mermaid), API reference, and a CHANGELOG.

---

## Suggested Next Session Checklist

- [ ] Pick 1-2 ideas above (recommend: **real labeled data** then **Postgres**).
- [ ] Add the labeled dataset under `data/datasets/` and retrain the model.
- [ ] Re-run `pytest` (currently 80 passing) and verify CLI, dashboard, and API.
- [ ] Update PROGRESS.md + README, commit, and tag a new release.
