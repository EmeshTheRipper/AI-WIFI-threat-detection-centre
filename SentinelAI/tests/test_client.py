"""Tests for the SentinelAI API HTTP client.

The client is exercised against the real FastAPI app through Starlette's
``TestClient`` (an ``httpx.Client`` subclass injected as the transport), which
proves every dashboard action reaches an actual API endpoint. A separate test
covers the in-process fallback when the backend is unreachable.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.client import SentinelClient
from src.api.server import app
from src.db import Database

SAMPLE = Path("data/samples/level2_sample.pcap")


def make_api_client(monkeypatch: pytest.MonkeyPatch) -> SentinelClient:
    """Build a client whose HTTP layer talks to the FastAPI app in-process."""
    app.state.db = Database("sqlite:///:memory:")
    transport_client = TestClient(app)
    client = SentinelClient(base_url="http://testserver")
    monkeypatch.setattr(SentinelClient, "_client", lambda self: transport_client)
    return client


def test_health_via_api(monkeypatch):
    client = make_api_client(monkeypatch)
    assert client.health() is True
    assert client.using_api is True


def test_analyze_default_via_api(monkeypatch):
    client = make_api_client(monkeypatch)
    result = client.analyze_default()
    assert result["packets"] == 61
    assert result["analysis_id"] is not None
    assert client.using_api is True


def test_analyze_upload_via_api(monkeypatch):
    client = make_api_client(monkeypatch)
    result = client.analyze_upload(SAMPLE.read_bytes(), "sample.pcap")
    assert result["source"] == "upload"
    assert result["packets"] == 61

    analyses = client.list_analyses()
    assert len(analyses) >= 1

    incidents = client.list_incidents(analysis_id=result["analysis_id"])
    assert len(incidents) >= 51
    assert "risk_score" in incidents[0]
    for f in Path("data/uploads").glob("*_sample.pcap"):
        f.unlink()


def test_list_incidents_all_via_api(monkeypatch):
    client = make_api_client(monkeypatch)
    client.analyze_default()
    incidents = client.list_incidents()
    assert isinstance(incidents, list)
    assert len(incidents) >= 51


def test_local_fallback_when_api_down():
    client = SentinelClient(base_url="http://127.0.0.1:1", fallback=True, timeout=5.0)
    assert client.health() is False
    result = client.analyze_default()
    assert client.using_api is False
    assert result["packets"] == 61
    assert result["analysis_id"] is not None