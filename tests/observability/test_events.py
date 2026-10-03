import pytest
from pydantic import ValidationError

from app.observability.schemas import EventType, SecurityEvent


def test_valid_event():
    ev = SecurityEvent(request_id="abc-123", event_type="PII_DETECTED", category="email", confidence=0.9)
    assert ev.category == "EMAIL" and ev.event_type is EventType.PII_DETECTED and len(ev.event_id) == 36


def test_missing_request_id():
    with pytest.raises(ValidationError):
        SecurityEvent(event_type="PII_DETECTED")


def test_invalid_request_id_chars():
    with pytest.raises(ValidationError):
        SecurityEvent(request_id="x'; DROP TABLE requests;--", event_type="PII_DETECTED")


def test_invalid_severity_and_type_and_confidence():
    with pytest.raises(ValidationError):
        SecurityEvent(request_id="r1", event_type="PII_DETECTED", severity="apocalyptic")
    with pytest.raises(ValidationError):
        SecurityEvent(request_id="r1", event_type="NOT_AN_EVENT")
    with pytest.raises(ValidationError):
        SecurityEvent(request_id="r1", event_type="PII_DETECTED", confidence=1.5)


def test_client_event_id_not_trusted(svc):
    ev = svc.record_event("PII_DETECTED", "r1", category="EMAIL")
    assert ev is not None
    assert svc.list_events()[0]["event_id"] == ev.event_id
    with pytest.raises(ValidationError):  # extra fields (e.g. client-supplied ids via kwargs) are forbidden
        SecurityEvent(request_id="r1", event_type="PII_DETECTED", bogus=1)


def test_service_strict_vs_lenient(svc):
    with pytest.raises(ValueError):
        svc.record_event("BAD_TYPE", "r1")
    svc.strict = False
    assert svc.record_event("BAD_TYPE", "r1") is None  # never breaks the proxy
