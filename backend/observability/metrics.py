"""Pure metric calculations over repository rows (no I/O, easy to test)."""
from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Sequence


def percentile(values: Sequence[float], pct: float) -> float:
    """Linear-interpolated percentile (pct in 0..100). Returns 0.0 for empty input."""
    if not values:
        return 0.0
    xs = sorted(values)
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * pct / 100.0
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return float(xs[lo] + (xs[hi] - xs[lo]) * (k - lo))


def _event_count(e: dict[str, Any]) -> int:
    c = e.get("metadata", {}).get("count")
    return int(c) if isinstance(c, (int, float)) and c >= 0 else 1


def compute_request_metrics(requests: Iterable[dict[str, Any]]) -> dict[str, Any]:
    reqs = list(requests)
    lats = [r["latency_ms"] for r in reqs if r.get("latency_ms") is not None]
    return {
        "total_requests": len(reqs),
        "successful_requests": sum(r["status"] == "completed" for r in reqs),
        "failed_requests": sum(r["status"] == "failed" for r in reqs),
        "blocked_requests": sum(r["decision"] == "BLOCKED" for r in reqs),
        "allowed_requests": sum(r["decision"] == "ALLOWED" for r in reqs),
        "avg_latency_ms": round(sum(lats) / len(lats), 2) if lats else 0.0,
        "p50_latency_ms": round(percentile(lats, 50), 2),
        "p95_latency_ms": round(percentile(lats, 95), 2),
        "p99_latency_ms": round(percentile(lats, 99), 2),
        "total_tokens": sum(r["total_tokens"] for r in reqs),
        "prompt_tokens": sum(r["prompt_tokens"] for r in reqs),
        "completion_tokens": sum(r["completion_tokens"] for r in reqs),
        "requests_by_model": dict(Counter(r["model"] or "unknown" for r in reqs)),
        "requests_by_provider": dict(Counter(r["provider"] or "unknown" for r in reqs)),
        "requests_by_status": dict(Counter(r["status"] for r in reqs)),
        "requests_by_decision": dict(Counter(r["decision"] or "NONE" for r in reqs)),
    }


def compute_security_summary(requests: Iterable[dict[str, Any]], events: Iterable[dict[str, Any]]
                             ) -> dict[str, Any]:
    reqs, evs = list(requests), list(events)
    by_type: dict[str, list[dict[str, Any]]] = {}
    for e in evs:
        by_type.setdefault(e["event_type"], []).append(e)

    pii_by_cat: Counter[str] = Counter()
    for e in by_type.get("PII_DETECTED", []):
        pii_by_cat[e.get("category") or "UNKNOWN"] += _event_count(e)
    inj = by_type.get("PROMPT_INJECTION_DETECTED", [])
    blocked_inj = sum(e.get("decision") in {"BLOCK", "BLOCKED"} for e in inj)
    inj_requests = sum(r["injection_detected"] for r in reqs)
    n_ph = lambda t: sum(_event_count(e) for e in by_type.get(t, []))
    ph_created, ph_restored = n_ph("PLACEHOLDER_CREATED"), n_ph("PLACEHOLDER_RESTORED")
    ph_reqs = [r for r in reqs if r["placeholder_count"] > 0]
    return {
        "pii": {
            "total_detections": sum(pii_by_cat.values()),
            "by_category": dict(pii_by_cat),
            "requests_with_pii": sum(r["pii_count"] > 0 for r in reqs),
            "redactions": n_ph("SENSITIVE_DATA_REDACTED"),
        },
        "prompt_injection": {
            "total_detections": len(inj),
            "blocked": blocked_inj,
            "allowed_or_suspicious": len(inj) - blocked_inj,
            "detection_rate": round(inj_requests / len(reqs), 4) if reqs else 0.0,
            "requests_blocked_for_injection": sum(
                r["injection_detected"] and r["decision"] == "BLOCKED" for r in reqs),
        },
        "placeholders": {
            "created": ph_created,
            "restored": ph_restored,
            "avg_per_request": round(sum(r["placeholder_count"] for r in reqs) / len(reqs), 2) if reqs else 0.0,
            "requests_with_placeholders": len(ph_reqs),
        },
        "events_by_severity": dict(Counter(e["severity"] for e in evs)),
        "events_by_type": {k: len(v) for k, v in by_type.items()},
    }


def compute_llm_metrics(calls: Iterable[dict[str, Any]]) -> dict[str, Any]:
    cs = list(calls)
    by_model: dict[str, dict[str, float]] = {}
    for c in cs:
        m = by_model.setdefault(f"{c['provider']}/{c['model']}",
                                {"calls": 0, "total_tokens": 0, "avg_latency_ms": 0.0, "errors": 0})
        m["calls"] += 1
        m["total_tokens"] += c["total_tokens"]
        m["avg_latency_ms"] += c["latency_ms"]
        m["errors"] += c["status"] != "success"
    for m in by_model.values():
        m["avg_latency_ms"] = round(m["avg_latency_ms"] / m["calls"], 2)
    costs = [c["estimated_cost"] for c in cs if c.get("estimated_cost") is not None]
    return {"total_calls": len(cs), "by_model": by_model,
            "estimated_cost": round(sum(costs), 6) if costs else None}
