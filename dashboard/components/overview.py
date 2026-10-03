import plotly.express as px
import streamlit as st

from dashboard import metrics as dm

COLORS = {"Allowed": "#2e9e6b", "Blocked": "#e5484d", "Failed": "#f5a623"}


def top_metrics(summary: dict, sec: dict) -> None:
    c = st.columns(6)
    c[0].metric("Requests", summary["total_requests"])
    c[1].metric("Blocked", summary["blocked_requests"])
    c[2].metric("PII Detected", summary["pii_detections"])
    c[3].metric("Injection", summary["prompt_injection_detections"])
    c[4].metric("Tokens", dm.fmt_tokens(summary["total_tokens"]))
    c[5].metric("Avg Latency", f"{summary['avg_latency_ms']:.0f} ms")


def security_overview(req_df, m: dict, sec: dict) -> None:
    st.subheader("Security overview")
    a, b, c = st.columns([2, 1, 1])
    vol = dm.volume_over_time(req_df)
    if vol.empty:
        a.info("No requests in this selection.")
    else:
        a.plotly_chart(px.bar(vol, x="timestamp", y="requests", color="outcome", color_discrete_map=COLORS,
                              title="Request volume"), width="stretch")
    dec = dm.counts_df(m["requests_by_decision"], "decision")
    if not dec.empty:
        b.plotly_chart(px.pie(dec, names="decision", values="requests", hole=.55, title="Decisions"),
                       width="stretch")
    pii = dm.pii_by_category(sec)
    if pii.empty:
        c.info("No PII detections.")
    else:
        c.plotly_chart(px.bar(pii, x="detections", y="category", orientation="h", title="PII by category"),
                       width="stretch")
