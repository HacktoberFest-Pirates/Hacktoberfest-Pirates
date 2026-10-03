from datetime import datetime

from dashboard import metrics as dm


def _req(i, ts, decision="ALLOWED", status="completed", tokens=10, lat=100.0):
    return {"request_id": f"r{i}", "timestamp": ts, "status": status, "decision": decision, "model": "m",
            "provider": "p", "latency_ms": lat, "prompt_tokens": 5, "completion_tokens": 5,
            "total_tokens": tokens, "pii_count": 0, "placeholder_count": 0, "injection_detected": False,
            "error_type": None}


def test_volume_and_usage():
    df = dm.requests_df([_req(1, "2026-01-01T10:00:00"), _req(2, "2026-01-01T10:00:30", "BLOCKED", "blocked"),
                         _req(3, "2026-01-01T10:01:10", status="failed")])
    vol = dm.volume_over_time(df)
    assert set(vol["outcome"]) == {"Allowed", "Blocked", "Failed"} and vol["requests"].sum() == 3
    assert dm.usage_over_time(df)["total_tokens"].sum() == 30


def test_empty_frames():
    assert dm.volume_over_time(dm.requests_df([])).empty
    assert dm.pii_by_category({}).empty


def test_pii_by_category_sorted():
    df = dm.pii_by_category({"pii": {"by_category": {"EMAIL": 1, "PERSON": 5}}})
    assert df.iloc[0]["category"] == "PERSON"


def test_safe_text_hides_pii():
    out = dm.safe_text({"note": "rahul@example.test +91 98765 43210 sk-abcdef1234567890ABCDEF"})
    assert "rahul" not in out and "98765" not in out and "sk-abc" not in out


def test_time_window():
    assert dm.time_window("All time") is None
    assert dm.time_window("Last 1 hour", datetime(2026, 1, 1, 12)).startswith("2026-01-01T11:00:00")


def test_fmt_tokens():
    assert dm.fmt_tokens(15432) == "15.4K" and dm.fmt_tokens(12) == "12"
