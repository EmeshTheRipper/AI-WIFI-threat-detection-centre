"""FastAPI backend for SentinelAI.

Exposes analysis, incident, persistence, and live-capture endpoints so the
detection pipeline can be driven over HTTP. Every run is persisted into
``sentinelai.db`` and clients can stream results directly from the API.
"""

import logging
import time
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from src.api.analyzer import (
    capture_live_records,
    read_pcap_records,
    run_full_analysis,
)
from src.db import Database

logger = logging.getLogger(__name__)

app = FastAPI(title="SentinelAI API", version="2.0.0")

app.state.db = Database()

DEFAULT_PCAP = "data/samples/level2_sample.pcap"


class AnalyzeRequest(BaseModel):
    pcap: str


class LiveRequest(BaseModel):
    interface: str | None = None
    count: int = Field(default=50, ge=1)


class IncidentOut(BaseModel):
    src_ip: str
    risk_score: float
    risk_level: str
    events: int
    targets: int
    tactics: str
    techniques: str
    threat_category: str = ""
    confidence: float = 0.0


class FlowOut(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    verdict: str
    confidence: float
    reasons: list[str]
    rule_names: list[str]


class ExplanationOut(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str
    label: str
    top_feature: str
    top_shap: float
    reason: str


class AnalyzeResponse(BaseModel):
    analysis_id: int | None
    pcap: str
    source: str
    note: str | None = None
    packets: int
    flows: int
    verdict_counts: dict
    suspicious_alerts: int
    total_incidents: int
    critical_incidents: int
    max_risk_score: float
    summary: dict
    incidents: list[IncidentOut]
    flow_details: list[FlowOut]
    explanations: list[ExplanationOut]
    model_available: bool


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/analyze/default", response_model=AnalyzeResponse)
def analyze_default(request: Request) -> dict:
    """Analyze the built-in sample PCAP and return the full result."""
    return _require_pcap(request, DEFAULT_PCAP)


@app.post("/analyze", response_model=AnalyzeResponse)
def run_analyze(req: AnalyzeRequest, request: Request) -> dict:
    """Analyze a PCAP by on-disk path."""
    return _require_pcap(request, req.pcap)


@app.post("/analyze/upload", response_model=AnalyzeResponse)
def analyze_upload(request: Request, file: UploadFile = File(...)) -> dict:
    """Analyze an uploaded PCAP file and persist the run."""
    contents = file.file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    filename = Path(file.filename or "upload.pcap").name
    upload_dir = Path("data/uploads")
    upload_dir.mkdir(parents=True, exist_ok=True)
    dest = upload_dir / f"{int(time.time())}_{filename}"
    dest.write_bytes(contents)

    records = read_pcap_records(str(dest))
    return run_full_analysis(
        records, dest.name, "upload", db=request.app.state.db
    )


@app.post("/analyze/live", response_model=AnalyzeResponse)
def analyze_live(req: LiveRequest, request: Request) -> dict:
    """Sniff packets live from an interface and run the full pipeline."""
    records = capture_live_records(req.interface, req.count)
    label = f"live:{req.interface or 'default'}:{req.count}"
    return run_full_analysis(
        records, label, "live", db=request.app.state.db
    )


def _require_pcap(request: Request, pcap_path: str) -> dict:
    """Analyze a PCAP path, returning 404 when the file is missing."""
    if not Path(pcap_path).exists():
        raise HTTPException(status_code=404, detail=f"PCAP not found: {pcap_path}")
    records = read_pcap_records(pcap_path)
    return run_full_analysis(records, pcap_path, "sample", db=request.app.state.db)


@app.get("/incidents", response_model=list[IncidentOut])
def list_incidents(request: Request, analysis_id: int | None = None):
    db: Database = request.app.state.db
    rows = db.list_incidents(analysis_id)
    return [
        IncidentOut(
            src_ip=r["src_ip"],
            risk_score=r["risk_score"],
            risk_level=r["risk_level"],
            events=r["events"],
            targets=r["targets"],
            tactics=r["tactics"] or "",
            techniques=r["techniques"] or "",
            threat_category=r["threat_category"] if "threat_category" in r else "",
            confidence=r["confidence"] if "confidence" in r else 0.0,
        )
        for r in rows
    ]


@app.get("/analyses")
def list_analyses(request: Request):
    db: Database = request.app.state.db
    return db.list_analyses()