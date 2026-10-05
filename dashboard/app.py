"""AI Security Proxy - Security & Observability Dashboard (presentation layer only).

Run:  streamlit run dashboard/app.py
"""
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st  # noqa: E402

from dashboard import api_client as api  # noqa: E402
from dashboard import metrics as dm  # noqa: E402
from dashboard.components import llm_usage, overview, requests as req_ui, security, timeline  # noqa: E402

st.set_page_config(page_title="AI Security Proxy", page_icon="🛡️", layout="wide")
st.title("AI SECURITY PROXY")
st.caption("Security & Observability Dashboard · identifiers and counts only — no prompts or personal data are stored or shown")

# ---------------- sidebar: filters ----------------
with st.sidebar:
    st.header("Filters")
    window = st.selectbox("Time range", list(dm.TIME_RANGES), index=3)
    try:
        base_m = api.metrics({})
    except api.ApiError as exc:
        st.error(str(exc))
        st.stop()
    severity = st.selectbox("Severity", ["All", "low", "medium", "high", "critical"])
    event_type = st.selectbox("Event type", ["All", "REQUEST_RECEIVED", "PII_DETECTED", "SENSITIVE_DATA_REDACTED",
                                             "PLACEHOLDER_CREATED", "PLACEHOLDER_RESTORED",
                                             "PROMPT_INJECTION_DETECTED", "REQUEST_BLOCKED", "REQUEST_ALLOWED",
                                             "LLM_REQUEST_SENT", "LLM_RESPONSE_RECEIVED", "LLM_ERROR",
                                             "RESPONSE_SANITIZED", "REQUEST_COMPLETED", "REQUEST_FAILED"])
    model = st.selectbox("Model", ["All"] + sorted(k for k in base_m["requests_by_model"] if k != "unknown"))
    provider = st.selectbox("Provider", ["All"] + sorted(k for k in base_m["requests_by_provider"] if k != "unknown"))
    decision = st.selectbox("Decision", ["All", "ALLOWED", "BLOCKED", "REDACT"])
    status = st.selectbox("Status", ["All", "completed", "blocked", "failed", "in_progress"])
    st.divider()
    if st.button("🔄 Refresh", width="stretch"):
        st.rerun()
    auto = st.checkbox("Auto-refresh")
    interval = st.slider("Every (seconds)", 5, 60, 10, disabled=not auto)
    if os.getenv("OBSERVABILITY_DEMO_MODE", "").lower() in {"1", "true", "yes"}:
        if st.button("Generate demo data", width="stretch"):
            from app.observability.demo import generate_demo_data
            from app.observability.service import get_service
            generate_demo_data(get_service(), 100)
            st.rerun()
    try:
        h = api.health()
        st.caption(f"API: {h['status']} · content logging: {h['content_logging']}")
    except api.ApiError:
        pass

common = {"start_time": dm.time_window(window), "model": model, "provider": provider,
          "decision": decision, "status": status}
try:
    summary = api.summary(common)
    m = api.metrics(common)
    sec = api.security(common)
    req_df = dm.requests_df(api.requests_list(common))
    ev_df = dm.events_df(api.events({**common, "severity": severity, "event_type": event_type}))
except api.ApiError as exc:
    st.error(str(exc))
    st.stop()

if summary["total_requests"] == 0:
    st.info("No data yet. Generate synthetic data with `python scripts/generate_demo_events.py`.")

overview.top_metrics(summary, sec)
overview.security_overview(req_df, m, sec)
security.threat_activity(ev_df, sec)
llm_usage.llm_usage(req_df, m)
req_ui.recent_requests(req_df, ev_df)

rid = req_ui.request_selector(req_df)
if rid:
    try:
        detail = api.request_detail(rid)
        req_ui.request_details(detail)
        timeline.security_timeline(detail)
    except api.ApiError as exc:
        st.warning(str(exc))

if auto:
    time.sleep(interval)
    st.rerun()
