"""HTTP client for the SentinelAI backend with in-process fallback.

Streamlit drives the web UI through this client so every action goes to the
FastAPI endpoints (``/analyze``, ``/analyze/upload``, ``/analyze/live``,
``/incidents``, ``/health``) and persists into ``sentinelai.db`` server-side.
When the backend is unreachable the client transparently runs the identical
analysis chain in-process so the dashboard never breaks.
"""

import logging
from pathlib import Path
from typing import Any

import httpx

from src.api.analyzer import (
    capture_live_records,
    read_pcap_records,
    run_full_analysis,
)
from src.db import Database

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SAMPLE = ROOT / "data" / "samples" / "level2_sample.pcap"

PCAP_MIME = "application/vnd.tcpdump.pcap"


class SentinelClientError(RuntimeError):
    """Raised when the backend is reachable but returns an error."""


class SentinelClient:
    """Talk to the SentinelAI API, falling back to local execution."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        fallback: bool = True,
        transport: object | None = None,
        timeout: float = 600.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.fallback = fallback
        self.transport = transport
        self.timeout = timeout
        self.mode = "api"
        self._db: Database | None = None

    def _client(self) -> httpx.Client:
        kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.transport is not None:
            kwargs["transport"] = self.transport
        return httpx.Client(base_url=self.base_url, **kwargs)

    @property
    def using_api(self) -> bool:
        return self.mode == "api"

    def health(self) -> bool:
        try:
            with self._client() as c:
                resp = c.get("/health")
                resp.raise_for_status()
                self.mode = "api"
                body = resp.json()
                return bool(isinstance(body, dict) and body.get("status") == "ok")
        except httpx.HTTPError:
            self.mode = "local" if self.fallback else "api"
            return False

    def analyze_upload(self, data: bytes, filename: str) -> dict:
        try:
            with self._client() as c:
                resp = c.post(
                    "/analyze/upload",
                    files={"file": (filename, data, PCAP_MIME)},
                )
                resp.raise_for_status()
                self.mode = "api"
                return dict(resp.json())
        except httpx.HTTPError as exc:
            if self._can_fallback(exc):
                self.mode = "local"
                return self._local_upload(data, filename)
            raise SentinelClientError(str(exc)) from exc

    def analyze_path(self, path: str) -> dict:
        try:
            with self._client() as c:
                resp = c.post("/analyze", json={"pcap": path})
                resp.raise_for_status()
                self.mode = "api"
                return dict(resp.json())
        except httpx.HTTPError as exc:
            if self._can_fallback(exc):
                self.mode = "local"
                return self._local_path(path)
            raise SentinelClientError(str(exc)) from exc

    def analyze_default(self) -> dict:
        try:
            with self._client() as c:
                resp = c.get("/analyze/default")
                resp.raise_for_status()
                self.mode = "api"
                return dict(resp.json())
        except httpx.HTTPError as exc:
            if self._can_fallback(exc):
                self.mode = "local"
                return self._local_path(str(DEFAULT_SAMPLE))
            raise SentinelClientError(str(exc)) from exc

    def analyze_live(self, interface: str | None = None, count: int = 50) -> dict:
        try:
            with self._client() as c:
                resp = c.post(
                    "/analyze/live",
                    json={"interface": interface, "count": count},
                )
                resp.raise_for_status()
                self.mode = "api"
                return dict(resp.json())
        except httpx.HTTPError as exc:
            if self._can_fallback(exc):
                self.mode = "local"
                return self._local_live(interface, count)
            raise SentinelClientError(str(exc)) from exc

    def list_analyses(self) -> list[dict]:
        try:
            with self._client() as c:
                resp = c.get("/analyses")
                resp.raise_for_status()
                self.mode = "api"
                return list(resp.json())
        except httpx.HTTPError as exc:
            if self._can_fallback(exc):
                self.mode = "local"
                return self._db_handle().list_analyses()
            raise SentinelClientError(str(exc)) from exc

    def list_incidents(self, analysis_id: int | None = None) -> list[dict]:
        try:
            with self._client() as c:
                resp = c.get(
                    "/incidents", params={"analysis_id": analysis_id} if analysis_id else {}
                )
                resp.raise_for_status()
                self.mode = "api"
                return list(resp.json())
        except httpx.HTTPError as exc:
            if self._can_fallback(exc):
                self.mode = "local"
                return self._db_handle().list_incidents(analysis_id)
            raise SentinelClientError(str(exc)) from exc

    def _can_fallback(self, exc: httpx.HTTPError) -> bool:
        return self.fallback and isinstance(
            exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout)
        )

    def _db_handle(self) -> Database:
        if self._db is None:
            self._db = Database()
        return self._db

    def _local_upload(self, data: bytes, filename: str) -> dict:
        upload_dir = ROOT / "data" / "uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        dest = upload_dir / f"local_{filename}"
        dest.write_bytes(data)
        records = read_pcap_records(str(dest))
        return run_full_analysis(records, dest.name, "upload", db=self._db_handle())

    def _local_path(self, path: str) -> dict:
        if not Path(path).exists():
            raise SentinelClientError(f"PCAP not found: {path}")
        records = read_pcap_records(path)
        return run_full_analysis(records, path, "sample", db=self._db_handle())

    def _local_live(self, interface: str | None, count: int) -> dict:
        records = capture_live_records(interface, count)
        label = f"live:{interface or 'default'}:{count}"
        return run_full_analysis(records, label, "live", db=self._db_handle())