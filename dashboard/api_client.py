"""Thin HTTP client for the observability API (dashboard never touches the database)."""
from __future__ import annotations

import os
from typing import Any, Optional

import requests

BASE_URL = os.getenv("OBSERVABILITY_API_URL", "http://localhost:8001").rstrip("/")
TIMEOUT = 10


class ApiError(RuntimeError):
    pass


def _get(path: str, params: Optional[dict[str, Any]] = None) -> Any:
    clean = {k: v for k, v in (params or {}).items() if v not in (None, "", "All")}
    try:
        r = requests.get(f"{BASE_URL}/observability{path}", params=clean, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as exc:
        raise ApiError(f"Observability API unavailable at {BASE_URL} ({type(exc).__name__})") from exc


def health() -> dict: return _get("/health")
def summary(p: dict) -> dict: return _get("/summary", p)
def metrics(p: dict) -> dict: return _get("/metrics", p)
def security(p: dict) -> dict: return _get("/security", p)
def requests_list(p: dict) -> list[dict]: return _get("/requests", {**p, "limit": 1000})["items"]
def events(p: dict) -> list[dict]: return _get("/events", {**p, "limit": 1000})["items"]
def request_detail(request_id: str) -> dict: return _get(f"/requests/{request_id}")
