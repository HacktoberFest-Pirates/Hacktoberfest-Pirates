import plotly.express as px
import streamlit as st

from dashboard import metrics as dm


def threat_activity(ev_df, sec: dict) -> None:
    st.subheader("Threat activity")
    inj, pii, ph = sec["prompt_injection"], sec["pii"], sec["placeholders"]
    c = st.columns(5)
    c[0].metric("Injection detections", inj["total_detections"])
    c[1].metric("Blocked", inj["blocked"])
    c[2].metric("Allowed / suspicious", inj["allowed_or_suspicious"])
    c[3].metric("Detection rate", f"{inj['detection_rate']:.1%}")
    c[4].metric("Requests with PII", pii["requests_with_pii"])
    c = st.columns(4)
    c[0].metric("Redactions", pii["redactions"])
    c[1].metric("Placeholders created", ph["created"])
    c[2].metric("Placeholders restored", ph["restored"])
    c[3].metric("Avg placeholders / request", ph["avg_per_request"])

    if ev_df.empty:
        st.info("No security events in this selection.")
        return
    sev_order = ["low", "medium", "high", "critical"]
    fig = px.scatter(ev_df, x="timestamp", y="event_type", color="severity",
                     color_discrete_map=dm.SEVERITY_COLORS, category_orders={"severity": sev_order},
                     hover_data=["request_id", "decision", "category"], title="Security event timeline")
    st.plotly_chart(fig, width="stretch")

    high = ev_df[ev_df["severity"].isin(["high", "critical"]) | ev_df["event_type"].isin(dm.HIGHLIGHT_EVENTS)]
    with st.expander(f"High-severity events ({len(high)})", expanded=len(high) > 0):
        st.dataframe(high.head(200).style.map(dm.style_severity, subset=["severity"]),
                     width="stretch", hide_index=True)
    with st.expander("All events"):
        st.dataframe(ev_df.head(500).style.map(dm.style_severity, subset=["severity"]),
                     width="stretch", hide_index=True)
