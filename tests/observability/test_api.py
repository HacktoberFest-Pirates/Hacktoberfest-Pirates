import pytest
from fastapi.testclient import TestClient

from app.observability.api import create_app
from tests.observability.test_metrics import seed


@pytest.fixture()
def client(svc):
    seed(svc)
    return TestClient(create_app())


def test_summary(client):
    j = client.get("/observability/summary").json()
    assert j["total_requests"] == 4 and j["pii_detections"] == 3


def test_requests_and_filters(client):
    j = client.get("/observability/requests", params={"decision": "BLOCKED"}).json()
    assert j["total"] == 1 and j["items"][0]["request_id"] == "b"
    assert client.get("/observability/requests", params={"limit": 2}).json()["items"].__len__() == 2


def test_request_detail_timeline(client):
    j = client.get("/observability/requests/a").json()
    assert j["status"] == "completed" and j["timeline"][0]["event"] == "REQUEST_RECEIVED"
    assert client.get("/observability/requests/nope").status_code == 404
    assert client.get("/observability/requests/bad%20id!").status_code in (404, 422)


def test_events_filters(client):
    j = client.get("/observability/events", params={"event_type": "PII_DETECTED"}).json()
    assert len(j["items"]) == 2
    assert client.get("/observability/events", params={"severity": "high"}).json()["items"]
    assert client.get("/observability/events", params={"severity": "bogus"}).status_code == 422
    assert client.get("/observability/events", params={"limit": 99999}).status_code == 422


def test_security_metrics_health(client):
    assert client.get("/observability/security").json()["pii"]["total_detections"] == 3
    assert client.get("/observability/metrics").json()["total_tokens"] == 170
    h = client.get("/observability/health").json()
    assert h["status"] == "ok" and h["content_logging"] == "disabled"


def test_read_only(client):
    assert client.post("/observability/events", json={}).status_code == 405
