"""FastAPI backend for SentinelAI.

Exposes analysis, incident, and persistence endpoints so the detection
pipeline can be driven over HTTP. Reuses the dashboard pipeline for the
shared analysis chain.
"""

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from src.mitre import annotate_incident
from src.dashboard import analyze
from src.db import Database

logger = logging.getLogger(__name__)

app = FastAPI(title="SentinelAI API", version="1.0.0")

app.state.db = Database()

DEFAULT_PCAP = "data/samples/level2_sample.pcap"


class AnalyzeRequest(BaseModel):
    pcap: str


class IncidentOut(BaseModel):
    src_ip: str
    risk_score: float
    risk_level: str
    events: int
    targets: int
    tactics: str
    techniques: str


class AnalyzeResponse(BaseModel):
    analysis_id: int
    pcap: str
    packets: int
    flows: int
    total_incidents: int
    summary: dict
    incidents: list[IncidentOut]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/analyze/default")
def analyze_default(request: Request):
    """Analyze the built-in sample PCAP and return the summary."""
    req = AnalyzeRequest(pcap=DEFAULT_PCAP)
    return run_analyze_core(request, req)


@app.post("/analyze", response_model=AnalyzeResponse)
def run_analyze(req: AnalyzeRequest, request: Request):
    return run_analyze_core(request, req)


def run_analyze_core(request: Request, req: AnalyzeRequest) -> AnalyzeResponse:
    db: Database = request.app.state.db
    if not Path(req.pcap).exists():
        raise HTTPException(status_code=404, detail=f"PCAP not found: {req.pcap}")

    result = analyze(req.pcap)

    analysis_id = db.save_analysis(
        req.pcap, result.packets, result.flows, len(result.scored)
    )

    incident_rows = []
    incidents_out = []
    for s in result.scored:
        ann = annotate_incident(s.incident)
        out = IncidentOut(
            src_ip=s.src_ip,
            risk_score=s.score,
            risk_level=s.level,
            events=s.incident.total_events,
            targets=s.incident.unique_targets,
            tactics=", ".join(ann["tactics"]),
            techniques=", ".join(ann["technique_ids"]),
        )
        incident_rows.append({
            "analysis_id": analysis_id,
            "src_ip": out.src_ip,
            "risk_score": out.risk_score,
            "risk_level": out.risk_level,
            "events": out.events,
            "targets": out.targets,
            "tactics": out.tactics,
            "techniques": out.techniques,
        })
        incidents_out.append(out)

    db.save_incidents(analysis_id, incident_rows)

    return AnalyzeResponse(
        analysis_id=analysis_id,
        pcap=str(req.pcap),
        packets=result.packets,
        flows=result.flows,
        total_incidents=len(result.scored),
        summary=result.summary,
        incidents=incidents_out,
    )


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
        )
        for r in rows
    ]


@app.get("/analyses")
def list_analyses(request: Request):
    db: Database = request.app.state.db
    return db.list_analyses()
