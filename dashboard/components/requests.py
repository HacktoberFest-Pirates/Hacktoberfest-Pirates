from typing import Optional
import streamlit as st
from dashboard import metrics as dm
import pandas as pd

def recent_requests(req_df, ev_df=None) -> None:
    st.subheader("Recent requests")
    if req_df.empty:
        st.info("No requests in this selection.")
        return
        
    view = req_df[["request_id", "timestamp", "model", "decision", "status", "pii_count",
                   "injection_detected", "latency_ms"]].head(200).copy()
    
    # Extract prompt previews if ev_df is available
    prompts = {}
    changed_prompts = {}
    if ev_df is not None and not ev_df.empty and "metadata" in ev_df.columns:
        for _, row in ev_df.iterrows():
            meta = row["metadata"] or {}
            rid = row["request_id"]
            if row["event_type"] == "REQUEST_RECEIVED" and "original_content" in meta:
                prompts[rid] = meta["original_content"]
            elif row["event_type"] == "LLM_REQUEST_SENT" and "sanitized_content" in meta:
                changed_prompts[rid] = meta["sanitized_content"]

    view["prompt_sent"] = view["request_id"].map(lambda x: str(prompts.get(x, ""))[:150] + ("..." if len(str(prompts.get(x, ""))) > 150 else ""))
    view["changed_prompt"] = view["request_id"].map(lambda x: str(changed_prompts.get(x, ""))[:150] + ("..." if len(str(changed_prompts.get(x, ""))) > 150 else ""))

    view["injection_detected"] = view["injection_detected"].map({True: "DETECTED", False: "-"})
    view["latency_ms"] = view["latency_ms"].round(0)
    
    # Reorder columns
    cols = ["timestamp", "request_id", "prompt_sent", "changed_prompt", "decision", "status", "pii_count", "injection_detected"]
    view = view[cols]
    
    st.dataframe(view, width="stretch", hide_index=True)


def request_selector(req_df) -> Optional[str]:
    st.subheader("Search Request Details")
    search_id = st.text_input("Enter Request ID to see full details (e.g. req_...)")
    if search_id and search_id.strip() != "":
        return search_id.strip()
    return None


def request_details(detail: dict) -> None:
    r = detail["request"]
    st.subheader("Request details")
    
    c = st.columns(4)
    c[0].markdown(f"**Request ID**  \\n`{r['request_id']}`")
    c[1].metric("Decision", r["decision"] or "-")
    c[2].metric("Status", r["status"].upper())
    c[3].metric("Latency", f"{(r['latency_ms'] or 0):.0f} ms")
    
    c = st.columns(4)
    c[0].markdown(f"**Timestamp**  \\n{r['timestamp']}")
    c[1].markdown(f"**Model / provider**  \\n{r['model'] or '-'} / {r['provider'] or '-'}")
    c[2].markdown(f"**PII entities / placeholders**  \\n{r['pii_count']} / {r['placeholder_count']}")
    c[3].markdown(f"**Injection**  \\n{'DETECTED' if r['injection_detected'] else 'none'}")
    
    st.caption(f"Tokens: prompt {r['prompt_tokens']} | completion {r['completion_tokens']} | "
               f"total {r['total_tokens']}" + (f" | error category: {r['error_type']}" if r["error_type"] else ""))
               
    # Display the full prompt and changed prompt if available in events
    events = detail.get("timeline", [])
    original = None
    sanitized = None
    for ev in events:
        if ev.get("event") == "REQUEST_RECEIVED":
            original = ev.get("metadata", {}).get("original_content")
        elif ev.get("event") == "LLM_REQUEST_SENT":
            sanitized = ev.get("metadata", {}).get("sanitized_content")
            
    if original or sanitized:
        st.divider()
        st.markdown("**Original Prompt:**")
        st.code(original or "N/A", language="text")
        st.markdown("**Modified Prompt (Sent to LLM):**")
        st.code(sanitized or "N/A", language="text")
