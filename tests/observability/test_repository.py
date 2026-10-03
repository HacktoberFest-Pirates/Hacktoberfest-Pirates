from datetime import timedelta

from backend.observability.repository import QueryFilters
from backend.observability.schemas import utcnow


def test_save_and_retrieve_event(svc):
    ev = svc.record_event("PII_DETECTED", "r1", category="EMAIL", metadata={"count": 2})
    got = svc.repo.get_security_events(request_id="r1")
    assert got[0]["event_id"] == ev.event_id and got[0]["metadata"] == {"count": 2}


def test_request_rollup(svc):
    svc.record_event("REQUEST_RECEIVED", "r1")
    svc.record_event("PII_DETECTED", "r1", category="EMAIL", metadata={"count": 2})
    svc.record_event("PLACEHOLDER_CREATED", "r1", metadata={"count": 2})
    svc.record_event("PROMPT_INJECTION_DETECTED", "r1", decision="BLOCK", metadata={"confidence": 0.97})
    svc.record_event("REQUEST_BLOCKED", "r1", decision="BLOCK")
    r = svc.get_request("r1")
    assert (r["pii_count"], r["placeholder_count"], r["injection_detected"]) == (2, 2, True)
    assert r["decision"] == "BLOCKED" and r["status"] == "blocked"


def test_blocked_is_terminal(svc):
    svc.record_event("REQUEST_BLOCKED", "r1")
    svc.record_event("REQUEST_ALLOWED", "r1")
    assert svc.get_request("r1")["decision"] == "BLOCKED"


def test_llm_call_and_failure(svc):
    svc.record_llm_call("r1", "openai", "gpt-4o-mini", 10, 20, 500)
    svc.finalize_request("r1", "completed", latency_ms=520)
    svc.record_llm_call("r2", "openai", "gpt-4o-mini", status="error", error_type="PROVIDER_TIMEOUT")
    svc.finalize_request("r2", "failed", error_type="PROVIDER_TIMEOUT")
    r1, r2 = svc.get_request("r1"), svc.get_request("r2")
    assert (r1["total_tokens"], r1["status"], r1["model"]) == (30, "completed", "gpt-4o-mini")
    assert (r2["status"], r2["error_type"]) == ("failed", "PROVIDER_TIMEOUT")


def test_filters_and_pagination(svc):
    for i in range(5):
        svc.record_llm_call(f"r{i}", "openai" if i % 2 else "local", "m", 1, 1, 1)
    assert len(svc.repo.list_requests(QueryFilters(provider="openai"))) == 2
    assert len(svc.repo.list_requests(QueryFilters(limit=2, offset=1))) == 2
    assert svc.repo.count_requests() == 5


def test_retention_purge(svc):
    svc.record_event("REQUEST_RECEIVED", "old", timestamp=utcnow() - timedelta(days=30))
    svc.record_event("REQUEST_RECEIVED", "new")
    assert svc.purge_expired() == 1
    assert svc.get_request("old") is None and svc.get_request("new") is not None


def test_timeline_order(svc):
    for et in ["REQUEST_RECEIVED", "PII_DETECTED", "LLM_REQUEST_SENT", "REQUEST_COMPLETED"]:
        svc.record_event(et, "r1")
    assert [e["event"] for e in svc.get_request_timeline("r1")["timeline"]] == \
        ["REQUEST_RECEIVED", "PII_DETECTED", "LLM_REQUEST_SENT", "REQUEST_COMPLETED"]
