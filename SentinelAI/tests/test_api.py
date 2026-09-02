"""Tests for the SentinelAI FastAPI backend."""

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
