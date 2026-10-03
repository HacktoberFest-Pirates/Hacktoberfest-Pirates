# API Reference — AI Security Proxy

## Base URL

```
http://localhost:8000
```

---

## Endpoints

### `GET /health`

Liveness probe.

**Response** `200 OK`

```json
{
  "status": "healthy",
  "service": "ai-security-proxy",
  "version": "0.1.0"
}
```

---

### `GET /ready`

Readiness probe — checks subsystem health.

**Response** `200 OK`

```json
{
  "status": "ready",
  "checks": {
    "pipeline": true,
    "llm_router": true,
    "llm_providers": true
  }
}
```

---

### `POST /v1/chat/completions`

OpenAI-compatible chat completion endpoint with security enforcement.

**Request**

```json
{
  "model": "demo-model",
  "messages": [
    {
      "role": "user",
      "content": "My email is alice@example.com"
    }
  ],
  "temperature": 0.7,
  "max_tokens": 100,
  "user": "user_42"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `model` | string | yes | Model identifier |
| `messages` | array | yes | Chat messages |
| `temperature` | float | no | Sampling temperature (default: 0.7) |
| `max_tokens` | int | no | Max tokens in response |
| `user` | string | no | User identifier |

**Response** `200 OK`

```json
{
  "id": "req_a1b2c3d4",
  "object": "chat.completion",
  "model": "demo-model",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Response text here..."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 10,
    "completion_tokens": 20,
    "total_tokens": 30
  }
}
```

**Error** `403 Forbidden` — Request blocked by security policy

```json
{
  "detail": {
    "error": "Request blocked by security policy.",
    "request_id": "req_a1b2c3d4"
  }
}
```

**Error** `502 Bad Gateway` — LLM provider error

```json
{
  "detail": {
    "error": "LLM provider error.",
    "request_id": "req_a1b2c3d4"
  }
}
```

---

### `GET /v1/stats`

Aggregate security statistics (for dashboard consumption).

**Response** `200 OK`

```json
{
  "total_events": 127,
  "requests_blocked": 19,
  "pii_detections": 43,
  "secret_detections": 12,
  "injection_detections": 5
}
```

---

### `GET /v1/events/{request_id}`

Retrieve all security events for a specific request.

**Response** `200 OK`

```json
[
  {
    "event_id": "evt_a1b2c3d4",
    "event_type": "REQUEST_RECEIVED",
    "timestamp": "2024-01-01T00:00:00Z",
    "decision": null,
    "risk_level": null,
    "metadata": {}
  }
]
```
