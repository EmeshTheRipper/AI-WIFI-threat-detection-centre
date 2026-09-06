"""Tests for the SentinelAI FastAPI backend."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.server import app
from src.db import Database


@pytest.fixture
def client():
    app.state.db = Database("sqlite:///:memory:")
    with TestClient(app) as c:
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_analyze_missing_pcap_404(client):
    resp = client.post("/analyze", json={"pcap": "does_not_exist.pcap"})
    assert resp.status_code == 404


def test_analyze_end_to_end(client):
    resp = client.post("/analyze", json={"pcap": "data/samples/level2_sample.pcap"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["packets"] == 61
    assert body["total_incidents"] == 51
    assert "incidents" in body
    assert isinstance(body["analysis_id"], int)
    assert body["incidents"][0]["risk_level"] in {"critical", "high", "medium", "low", "minimal"}


def test_analyze_default(client):
    resp = client.get("/analyze/default")
    assert resp.status_code == 200
    assert resp.json()["packets"] == 61


def test_incidents_endpoint(client):
    client.post("/analyze", json={"pcap": "data/samples/level2_sample.pcap"})
    resp = client.get("/incidents")
    assert resp.status_code == 200
    incidents = resp.json()
    assert isinstance(incidents, list)
    assert len(incidents) >= 51
    assert "risk_score" in incidents[0]


def test_analyses_endpoint(client):
    client.post("/analyze", json={"pcap": "data/samples/level2_sample.pcap"})
    resp = client.get("/analyses")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_analyze_upload(client):
    data = Path("data/samples/level2_sample.pcap").read_bytes()
    resp = client.post(
        "/analyze/upload",
        files={"file": ("sample.pcap", data, "application/vnd.tcpdump.pcap")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "upload"
    assert body["packets"] == 61
    assert isinstance(body["analysis_id"], int)
    assert "flow_details" in body
    assert "explanations" in body
    for f in Path("data/uploads").glob("*_sample.pcap"):
        f.unlink()


def test_analyze_upload_empty(client):
    resp = client.post(
        "/analyze/upload",
        files={"file": ("empty.pcap", b"", "application/vnd.tcpdump.pcap")},
    )
    assert resp.status_code == 400


def test_analyze_live_with_stubbed_capture(client, monkeypatch):
    from src.api.analyzer import read_pcap_records

    fake = read_pcap_records("data/samples/level2_sample.pcap")
    monkeypatch.setattr("src.api.server.capture_live_records", lambda i, c: fake)
    resp = client.post("/analyze/live", json={"interface": "eth0", "count": 5})
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "live"
    assert body["packets"] == 61


def test_analyze_rich_fields(client):
    resp = client.post("/analyze", json={"pcap": "data/samples/level2_sample.pcap"})
    body = resp.json()
    for key in [
        "verdict_counts",
        "suspicious_alerts",
        "critical_incidents",
        "max_risk_score",
        "flow_details",
        "explanations",
        "model_available",
    ]:
        assert key in body
    assert "threat_category" in body["incidents"][0]
