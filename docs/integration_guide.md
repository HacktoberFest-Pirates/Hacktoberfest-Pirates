# Integration Guide (Person 1 — Core Proxy / Gateway)

How to plug a detector, privacy engine, LLM provider or dashboard into the
AI Security Proxy **without editing the gateway**.

```
App ──► POST /v1/chat/completions ──► SecurityPipeline ──► LLM Router ──► Provider
                                         │  (per user message)
                          [your modules] ─┘ ... ► PolicyEngine (always last)
```

## 1. SecurityModule interface

Defined in `app/security/interfaces.py`.

```python
class SecurityModule:
    @property
    def name(self) -> str: ...                       # unique, kebab-case

    async def inspect(self, content: str, context: dict) -> SecurityResult: ...
```

`content` is the text of **one user message** (already sanitized by earlier
modules). `context` is shared by every module for the whole request:

| Key | Meaning |
|---|---|
| `request_id` | `req_xxxxxxxx`, stable for the whole request |
| `user_id` | from the request `user` field, may be `None` |
| `model` | requested model name |
| `detections` | list that detectors **append to**; the PolicyEngine reads it |

## 2. SecurityResult contract

| Field | Type | Rules |
|---|---|---|
| `decision` | `Decision.ALLOW / MODIFY / BLOCK` | `BLOCK` stops the pipeline; the LLM is never called |
| `module_name` | `str` | use `self.name` |
| `reason` | `str \| None` | short and static. **Never include prompt text** |
| `modified_content` | `str \| None` | required when `decision == MODIFY`; becomes the input of the next module |
| `metadata` | `dict \| None` | counts, types, rule names only |

**Detector convention (recommended):** return `ALLOW` (or `MODIFY` if you
redact) and append a dict to `context["detections"]`:

```python
context.setdefault("detections", []).append(
    {"type": "pii" | "secrets" | "prompt_injection" | "high_risk",
     "subtype": "email", "risk_level": "high"}
)
```

The PolicyEngine (`app/security/policy.py`) turns detections into the final
`allow / redact / block` using `POLICY_*_ACTION` settings. Do not hard-code
BLOCK inside a detector unless it is a hard safety rule.

## 3. Pipeline lifecycle

1. Request arrives → `request_id` generated → `REQUEST_RECEIVED` event.
2. For **each user message** (system/assistant messages pass through
   unchanged): run modules in order. `MODIFY` feeds the new text onward;
   `BLOCK` ends the request with HTTP 403.
3. A module that raises or exceeds `SECURITY_MODULE_TIMEOUT_S` is handled by
   `SECURITY_FAIL_CLOSED` (`false` = treated as ALLOW, `true` = BLOCK). Only
   the exception type is recorded.
4. Sanitized messages go to the LLM Router (`LLM_REQUEST`), with a
   `LLM_TIMEOUT_S` limit (504 on timeout, 502 on provider error).
5. `LLM_RESPONSE` → optional de-tokenization → `REQUEST_COMPLETED`.
6. The privacy engine's mapping for the request is **always** cleared at the
   end (success, block or failure).

Because `process` runs once per user message, `inspect` can be called several
times with the same `request_id`. Keep per-request state keyed by
`request_id` and merge, don't overwrite.

## 4. Optional privacy engine (de-tokenization)

If a module (stub: `PlaceholderDetector`) also provides these two methods it is
used for de-tokenization, selected automatically:

```python
def restore(self, request_id: str, text: str) -> str: ...
def clear_mapping(self, request_id: str) -> None: ...
```

Restoration happens only when `RESTORE_PLACEHOLDERS=true` or the request has
header `x-restore-placeholders: true`. Restored text goes only into the HTTP
response body, never into logs or events.

## 5. LLMProvider interface

Providers live in `app/proxy/upstream.py` and are registered in
`app/proxy/router.py` (see those files for the base class). The route relies on:

- `provider_name` attribute on the provider;
- `await router.generate(model=..., messages=[...], temperature=..., max_tokens=...)`
  returning an object with `.content`, `.model`, `.provider` and `.usage`
  (`dict` with `prompt_tokens`, `completion_tokens`, `total_tokens`);
- `await router.health_check()` → `dict[str, bool]` used by `/ready`.

`MOCK_LLM=true` (default) always uses the mock provider.

## 6. SecurityEvent schema

Defined in `app/observability/events.py`. Fields:
`event_id, request_id, user_id, event_type, timestamp, decision, risk_level, metadata`.

| `event_type` | `metadata` keys |
|---|---|
| `REQUEST_RECEIVED` | `model`, `message_count` |
| `PII_DETECTED` | `pii_count`, `types` |
| `SECRET_DETECTED` | `secret_count`, `subtype` |
| `PROMPT_INJECTION_DETECTED` | `rule`, `pattern` (our regex, not user text) |
| `REQUEST_SANITIZED` | `module`, `reason` |
| `REQUEST_BLOCKED` | `blocked_by`, `reason` |
| `LLM_REQUEST` | `provider` |
| `LLM_RESPONSE` | `provider`, `latency_ms`, `usage` |
| `REQUEST_COMPLETED` | `latency_ms`, `pipeline_ms`, `redactions` |
| `REQUEST_FAILED` | `error_type` (exception class name only) |

Read-only endpoints for the dashboard: `GET /v1/stats` (aggregate counters),
`GET /v1/events/{request_id}` (audit trail). **Events and logs must never
contain raw prompts, PII, secrets or API keys** — only types, counts, ids.

## 7. Plug a detector in (3 steps, no gateway edits)

1. Create your module anywhere in `app/` (e.g. `app/pii/presidio_module.py`):

   ```python
   from app.security.interfaces import Decision, SecurityModule, SecurityResult

   class PresidioPIIModule(SecurityModule):
       @property
       def name(self) -> str:
           return "presidio-pii"

       async def inspect(self, content: str, context: dict) -> SecurityResult:
           sanitized, found = my_detect_and_redact(content)   # your logic
           if not found:
               return SecurityResult(decision=Decision.ALLOW, module_name=self.name)
           context.setdefault("detections", []).append(
               {"type": "pii", "subtype": found[0]}
           )
           return SecurityResult(
               decision=Decision.MODIFY,
               module_name=self.name,
               reason=f"Redacted {len(found)} item(s).",
               modified_content=sanitized,
               metadata={"types": sorted(set(found))},
           )
   ```
   The class must be constructible with no arguments.

2. Enable it in `.env`:

   ```
   EXTRA_SECURITY_MODULES=app.pii.presidio_module:PresidioPIIModule
   ENABLE_STUB_DETECTORS=false      # turn off the regex demo stubs when yours replaces them
   ```
   Several modules: comma-separate the entries (they run in that order, before the PolicyEngine).

3. Test it: `pytest -q`, then `curl` the demo prompts. A bad entry fails at
   startup on purpose.

## 8. File ownership

**Person 1 owns (others: don't edit; open a PR or ask):**
`app/main.py`, `app/config/`, `app/api/`, `app/proxy/`,
`app/security/interfaces.py`, `app/security/policy.py`,
`app/observability/events.py`, `app/utils/`, `Dockerfile`,
`docker-compose.yml` (proxy service), `pytest.ini`, `.env.example`,
`tests/test_health.py`, `tests/test_proxy.py`, `tests/test_pipeline.py`,
`tests/test_hardening.py`, `docs/architecture.md`, `docs/integration_guide.md`.

**Demo stubs, to be replaced by teammates' modules (no gateway edits needed):**
`app/privacy/placeholder.py`, `app/security/prompt_injection.py`,
`tests/test_security.py`.

**Teammates own:** their detector/privacy/dashboard code and tests
(for example under `app/privacy/`, `tests/privacy/`, `docs/privacy/`), plus any
new folders they add.

**Frozen interfaces:** `SecurityModule`, `SecurityResult`, `Decision`,
`SecurityEvent` field names and the event types above. Changing them needs
agreement from everyone.
