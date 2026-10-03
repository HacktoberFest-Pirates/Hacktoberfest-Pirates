import plotly.express as px
import streamlit as st

from dashboard import metrics as dm


def llm_usage(req_df, m: dict) -> None:
    st.subheader("LLM usage")
    a, b, c = st.columns(3)
    models = dm.counts_df(m["requests_by_model"], "model")
    if models.empty:
        st.info("No LLM usage in this selection.")
        return
    a.plotly_chart(px.bar(models, x="model", y="requests", title="Requests by model"), width="stretch")
    usage = dm.usage_over_time(req_df)
    b.plotly_chart(px.line(usage, x="timestamp", y="total_tokens", title="Tokens over time"),
                   width="stretch")
    c.plotly_chart(px.line(usage, x="timestamp", y="latency_ms", title="Avg latency over time (ms)"),
                   width="stretch")
    lat = req_df.dropna(subset=["latency_ms"])
    d, e = st.columns([2, 1])
    d.plotly_chart(px.histogram(lat, x="latency_ms", nbins=30, title="Latency distribution"),
                   width="stretch")
    e.markdown("**Latency percentiles**")
    e.table({"p50": [f"{m['p50_latency_ms']:.0f} ms"], "p95": [f"{m['p95_latency_ms']:.0f} ms"],
             "p99": [f"{m['p99_latency_ms']:.0f} ms"]})
    e.caption(f"Prompt tokens {m['prompt_tokens']:,} · completion {m['completion_tokens']:,}")
