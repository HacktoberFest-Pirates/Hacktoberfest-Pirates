# Observability Integration Contract

Modules **emit events**; they never touch the database or dashboard.

```python
from backend.observability.service import observability   # lazy singleton, safe to import anywhere
```

All calls are **non-blocking** (background writer) and **never raise** into the caller (invalid events are
dropped with a warning log). Everything is sanitised before storage (see *Privacy*).

## Request lifecycle (proxy owner)
```python
request_id = observability.start_request()            # generates UUID + emits REQUEST_RECEIVED
# ... pipeline ...
observability.record_event("REQUEST_ALLOWED", request_id, source="policy_engine", decision="ALLOW")
observability.finalize_request(request_id, "completed", latency_ms=842)    # or "failed", error_type="PROVIDER_TIMEOUT"
```
If you already create your own id: `observability.start_request(request_id=my_id)`. IDs must match `[A-Za-z0-9_-]{1,64}`.

## Person 1 - PII / redaction / placeholders
```python
# one event per category - NEVER pass the matched text, only counts
observability.record_event("PII_DETECTED", request_id, source="pii_detector",
                           category="EMAIL", confidence=0.98, decision="REDACT", metadata={"count": 2})
observability.record_event("SENSITIVE_DATA_REDACTED", request_id, source="redactor", category="EMAIL", metadata={"count": 2})
observability.record_event("PLACEHOLDER_CREATED",  request_id, source="placeholder_engine", metadata={"count": 2})
observability.record_event("PLACEHOLDER_RESTORED", request_id, source="placeholder_engine", metadata={"count": 2})
```
`category` is any string (`EMAIL`, `PHONE`, `PERSON`, `API_KEY`, ...).

## Person 2 - prompt-injection / policy
```python
observability.record_event("PROMPT_INJECTION_DETECTED", request_id, source="prompt_guard",
                           severity="high", decision="BLOCK", metadata={"confidence": 0.94})
observability.record_event("REQUEST_BLOCKED", request_id, source="policy_engine", decision="BLOCK",
                           metadata={"reason_code": "PROMPT_INJECTION"})
```
`decision="ALLOW"` on an injection event records an *allowed/suspicious* detection.

## LLM router
```python
observability.record_event("LLM_REQUEST_SENT", request_id, source="llm_router")
observability.record_llm_call(request_id=request_id, provider="openai", model="gpt-4o-mini",
                              prompt_tokens=123, completion_tokens=456, latency_ms=842)   # emits LLM_RESPONSE_RECEIVED
# on provider failure (use an error *category*, never the raw exception text/credentials):
observability.record_llm_call(request_id, "openai", "gpt-4o-mini", status="error", error_type="PROVIDER_TIMEOUT")
observability.finalize_request(request_id, "failed", error_type="PROVIDER_TIMEOUT")
```

## Mounting the API in the main FastAPI app (optional, one line)
```python
from backend.observability.api import router as observability_router
app.include_router(observability_router)
```
Or run standalone: `uvicorn backend.observability.api:app --port 8001`.

## Event fields
`event_type` (enum below), `request_id`, `source`, `severity` (`low|medium|high|critical`; defaulted per type),
`decision`, `category`, `confidence` (0-1; also lifted from `metadata.confidence`), `message` (<=200 chars), `metadata` (dict).
`event_id` and `timestamp` are server-generated (a client-supplied `event_id` is not accepted).

Event types: REQUEST_RECEIVED, PII_DETECTED, SENSITIVE_DATA_REDACTED, PLACEHOLDER_CREATED, PLACEHOLDER_RESTORED,
PROMPT_INJECTION_CHECK, PROMPT_INJECTION_DETECTED, REQUEST_BLOCKED, REQUEST_ALLOWED, LLM_REQUEST_SENT,
LLM_RESPONSE_RECEIVED, LLM_ERROR, RESPONSE_SANITIZED, REQUEST_COMPLETED, REQUEST_FAILED.

Special `metadata` keys: `count` (entities/placeholders; default 1), `latency_ms` (on completed/failed/blocked), `error_type`.

## Privacy
Never send prompts, responses, matched PII, keys or tokens. As a safety net, `sanitize.py`:
drops content-like keys (`prompt, content, text, raw*, password, secret*, api_key, token, authorization, value, ...`),
scrubs emails / phones / cards / API keys / long secrets / IPs from every string, truncates strings to 200 chars, and
limits nesting. The dashboard applies a second display-side filter. Use `sanitize.fingerprint(text)` if you need a
one-way correlation hash.
