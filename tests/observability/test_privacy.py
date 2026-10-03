import json
import sqlite3

from app.observability.sanitize import sanitize_metadata, scrub_text

SECRETS = ["rahul@example.test", "+91 98765 43210", "sk-abcdef1234567890ABCDEF", "4111 1111 1111 1111"]


def test_scrub_text():
    out = scrub_text("mail rahul@example.test key sk-abcdef1234567890ABCDEF card 4111 1111 1111 1111")
    assert not any(s in out for s in SECRETS)


def test_forbidden_keys_dropped():
    meta = sanitize_metadata({"prompt": "my pw", "count": 2, "nested": {"api_key": "x", "ok": 1}, "password": "p"})
    assert meta == {"count": 2, "nested": {"ok": 1}}


def test_raw_pii_not_persisted(svc):
    svc.record_event("PII_DETECTED", "r1", category="EMAIL", message="found rahul@example.test",
                     metadata={"count": 1, "prompt": "my email is rahul@example.test",
                               "detail": "contact +91 98765 43210", "key": "sk-abcdef1234567890ABCDEF"})
    svc.record_event("REQUEST_FAILED", "r1", metadata={"error_type": "AUTH", "authorization": "Bearer sk-abcdef1234567890ABCDEF"})
    raw = sqlite3_dump(svc)
    api_view = json.dumps(svc.get_request_timeline("r1"), default=str)
    for s in SECRETS + ["Bearer"]:
        assert s not in raw and s not in api_view


def sqlite3_dump(svc) -> str:
    with svc.repo.engine.raw_connection() as c:
        return "\n".join(c.iterdump()) if hasattr(c, "iterdump") else \
            "\n".join(c.driver_connection.iterdump())
