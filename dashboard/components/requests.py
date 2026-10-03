from typing import Optional

import streamlit as st

from dashboard import metrics as dm


def recent_requests(req_df) -> None:
    st.subheader("Recent requests")
    if req_df.empty:
        st.info("No requests in this selection.")
        return
    view = req_df[["request_id", "timestamp", "model", "decision", "status", "pii_count",
                   "injection_detected", "latency_ms"]].head(200).copy()
    view["injection_detected"] = view["injection_detected"].map({True: "DETECTED", False: "-"})
    view["latency_ms"] = view["latency_ms"].round(0)
    st.dataframe(view, width="stretch", hide_index=True)


def request_selector(req_df) -> Optional[str]:
    if req_df.empty:
        return None
    ids = req_df["request_id"].head(200).tolist()
    return st.selectbox("Select a request to inspect", ids,
                        format_func=lambda i: f"{i[:8]}…  {req_df.set_index('request_id').loc[i, 'decision'] or '-'}")


def request_details(detail: dict) -> None:
    r = detail["request"]
    st.subheader("Request details")
    c = st.columns(4)
    c[0].markdown(f"**Request ID**  \n`{r['request_id']}`")
    c[1].metric("Decision", r["decision"] or "-")
    c[2].metric("Status", r["status"].upper())
    c[3].metric("Latency", f"{(r['latency_ms'] or 0):.0f} ms")
    c = st.columns(4)
    c[0].markdown(f"**Timestamp**  \n{r['timestamp']}")
    c[1].markdown(f"**Model / provider**  \n{r['model'] or '-'} / {r['provider'] or '-'}")
    c[2].markdown(f"**PII entities / placeholders**  \n{r['pii_count']} / {r['placeholder_count']}")
    c[3].markdown(f"**Injection**  \n{'DETECTED' if r['injection_detected'] else 'none'}")
    st.caption(f"Tokens: prompt {r['prompt_tokens']} · completion {r['completion_tokens']} · "
               f"total {r['total_tokens']}" + (f" · error category: {r['error_type']}" if r["error_type"] else ""))
