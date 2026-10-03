import pytest

from app.observability.metrics import percentile


def seed(svc):
    svc.record_event("REQUEST_RECEIVED", "a")
    svc.record_event("PII_DETECTED", "a", category="EMAIL", metadata={"count": 2})
    svc.record_event("PII_DETECTED", "a", category="PERSON", metadata={"count": 1})
    svc.record_event("PLACEHOLDER_CREATED", "a", metadata={"count": 3})
    svc.record_event("PLACEHOLDER_RESTORED", "a", metadata={"count": 3})
    svc.record_event("REQUEST_ALLOWED", "a")
    svc.record_llm_call("a", "openai", "gpt-4o-mini", 100, 50, 100)
    svc.finalize_request("a", "completed", latency_ms=100)
    svc.record_event("PROMPT_INJECTION_DETECTED", "b", decision="BLOCK", metadata={"confidence": 0.9})
    svc.record_event("REQUEST_BLOCKED", "b", decision="BLOCK")
    svc.record_llm_call("c", "google", "gemini-2.5-flash", 10, 10, 300)
    svc.finalize_request("c", "completed", latency_ms=300)
    svc.record_event("PROMPT_INJECTION_DETECTED", "c", decision="ALLOW")
    svc.finalize_request("d", "failed", latency_ms=900, error_type="TIMEOUT")


def test_percentiles():
    assert percentile([], 50) == 0.0
    assert percentile([10], 99) == 10
    assert percentile([1, 2, 3, 4, 5], 50) == 3
    assert percentile(list(range(1, 101)), 95) == pytest.approx(95.05)


def test_request_metrics(svc):
    seed(svc)
    m = svc.calculate_metrics()
    assert (m["total_requests"], m["blocked_requests"], m["allowed_requests"]) == (4, 1, 2)  # c is "allowed but suspicious"
    assert (m["successful_requests"], m["failed_requests"]) == (2, 1)
    assert m["avg_latency_ms"] == pytest.approx((100 + 300 + 900) / 3, abs=0.01)
    assert m["p50_latency_ms"] == 300
    assert (m["prompt_tokens"], m["completion_tokens"], m["total_tokens"]) == (110, 60, 170)
    assert m["requests_by_provider"]["openai"] == 1


def test_security_summary(svc):
    seed(svc)
    s = svc.get_security_summary()
    assert s["pii"]["total_detections"] == 3 and s["pii"]["by_category"] == {"EMAIL": 2, "PERSON": 1}
    assert s["pii"]["requests_with_pii"] == 1
    assert s["prompt_injection"]["total_detections"] == 2 and s["prompt_injection"]["blocked"] == 1
    assert s["prompt_injection"]["allowed_or_suspicious"] == 1
    assert s["prompt_injection"]["requests_blocked_for_injection"] == 1
    assert s["placeholders"]["created"] == 3 and s["placeholders"]["restored"] == 3


def test_summary_shape(svc):
    seed(svc)
    assert set(svc.summary()) == {"total_requests", "blocked_requests", "pii_detections",
                                  "prompt_injection_detections", "avg_latency_ms", "total_tokens"}
