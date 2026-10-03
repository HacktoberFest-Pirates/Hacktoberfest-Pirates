"""Pure data-transformation helpers for the dashboard (unit-testable, no Streamlit imports)."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pandas as pd

TIME_RANGES: dict[str, Optional[timedelta]] = {
    "Last 15 minutes": timedelta(minutes=15), "Last 1 hour": timedelta(hours=1),
    "Last 6 hours": timedelta(hours=6), "Last 24 hours": timedelta(hours=24),
    "Last 7 days": timedelta(days=7), "All time": None,
}
SEVERITY_COLORS = {"critical": "#b42318", "high": "#e5484d", "medium": "#f5a623", "low": "#4f8cff"}
HIGHLIGHT_EVENTS = {"PROMPT_INJECTION_DETECTED", "REQUEST_BLOCKED"}

# Defensive display filter: even if upstream leaked something, the UI will not render it.
_DISPLAY_SCRUB = [re.compile(p) for p in (
    r"[\w.+-]+@[\w-]+\.[\w.-]+", r"\b(?:sk|pk|gsk|AIza|ghp)[-_A-Za-z0-9]{12,}\b",
    r"\+?\d[\d\s().-]{8,}\d", r"\b[A-Za-z0-9+/_-]{32,}\b")]


def safe_text(value: Any) -> str:
    s = value if isinstance(value, str) else json.dumps(value, default=str)
    for p in _DISPLAY_SCRUB:
        s = p.sub("[hidden]", s)
    return s


def time_window(label: str, now: Optional[datetime] = None) -> Optional[str]:
    delta = TIME_RANGES.get(label)
    if delta is None:
        return None
    return ((now or datetime.now(timezone.utc)) - delta).replace(tzinfo=None).isoformat()


def requests_df(items: list[dict]) -> pd.DataFrame:
    cols = ["request_id", "timestamp", "status", "decision", "model", "provider", "latency_ms",
            "prompt_tokens", "completion_tokens", "total_tokens", "pii_count", "placeholder_count",
            "injection_detected", "error_type"]
    df = pd.DataFrame(items, columns=cols)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def events_df(items: list[dict]) -> pd.DataFrame:
    cols = ["timestamp", "request_id", "event_type", "severity", "source", "category", "decision", "confidence"]
    df = pd.DataFrame(items, columns=cols)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def bucket_freq(df: pd.DataFrame) -> str:
    if df.empty:
        return "1min"
    span = df["timestamp"].max() - df["timestamp"].min()
    return "1min" if span <= timedelta(hours=1) else "5min" if span <= timedelta(hours=6) \
        else "1h" if span <= timedelta(hours=48) else "1D"


def volume_over_time(df: pd.DataFrame) -> pd.DataFrame:
    """Requests per time bucket, split into Blocked / Failed / Allowed-or-other."""
    if df.empty:
        return pd.DataFrame(columns=["timestamp", "outcome", "requests"])
    d = df.copy()
    d["outcome"] = "Allowed"
    d.loc[d["status"] == "failed", "outcome"] = "Failed"
    d.loc[d["decision"] == "BLOCKED", "outcome"] = "Blocked"
    out = d.groupby([pd.Grouper(key="timestamp", freq=bucket_freq(d)), "outcome"]).size()
    return out.rename("requests").reset_index()


def usage_over_time(df: pd.DataFrame) -> pd.DataFrame:
    """Tokens (sum) and latency (mean) per bucket."""
    if df.empty:
        return pd.DataFrame(columns=["timestamp", "total_tokens", "latency_ms"])
    g = df.groupby(pd.Grouper(key="timestamp", freq=bucket_freq(df)))
    return g.agg(total_tokens=("total_tokens", "sum"), latency_ms=("latency_ms", "mean")).reset_index()


def pii_by_category(sec: dict) -> pd.DataFrame:
    cats = sec.get("pii", {}).get("by_category", {})
    return pd.DataFrame({"category": list(cats), "detections": list(cats.values())}).sort_values(
        "detections", ascending=False) if cats else pd.DataFrame(columns=["category", "detections"])


def counts_df(d: dict[str, int], key: str = "name") -> pd.DataFrame:
    return pd.DataFrame({key: list(d), "requests": list(d.values())})


def style_severity(severity: str) -> str:
    c = SEVERITY_COLORS.get(str(severity).lower(), "#888")
    return f"background-color: {c}22; color: {c}; font-weight: 600"


def fmt_tokens(n: float) -> str:
    return f"{n/1_000_000:.1f}M" if n >= 1e6 else f"{n/1000:.1f}K" if n >= 1000 else str(int(n))
