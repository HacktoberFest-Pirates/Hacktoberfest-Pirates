import streamlit as st

from dashboard import metrics as dm

LABELS = {"SENSITIVE_DATA_REDACTED": "REDACTED", "LLM_REQUEST_SENT": "LLM_REQUEST",
          "LLM_RESPONSE_RECEIVED": "LLM_RESPONSE", "REQUEST_COMPLETED": "COMPLETED"}


def security_timeline(detail: dict) -> None:
    st.markdown("#### Security timeline")
    steps = detail["timeline"]
    for i, e in enumerate(steps):
        color = dm.SEVERITY_COLORS.get(e["severity"], "#888")
        bold = e["event"] in dm.HIGHLIGHT_EVENTS
        bits = [b for b in (e.get("category"), e.get("decision"),
                            f"conf {e['confidence']:.2f}" if e.get("confidence") is not None else None) if b]
        meta = dm.safe_text(e["metadata"]) if e.get("metadata") else ""
        st.markdown(
            f"<div style='border-left:4px solid {color};padding:2px 10px;margin:0'>"
            f"<span style='font-weight:{700 if bold else 500}'>{LABELS.get(e['event'], e['event'])}</span> "
            f"<span style='color:{color};font-size:.8em'>{e['severity'].upper()}</span> "
            f"<span style='opacity:.65;font-size:.8em'>{e['source']} · {e['timestamp'][11:23]}"
            f"{' · ' + ' · '.join(bits) if bits else ''}</span>"
            f"<div style='opacity:.6;font-size:.75em'>{meta}</div></div>", unsafe_allow_html=True)
        if i < len(steps) - 1:
            st.markdown("<div style='margin-left:10px;opacity:.5'>↓</div>", unsafe_allow_html=True)
