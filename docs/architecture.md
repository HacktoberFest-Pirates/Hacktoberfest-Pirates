# Architecture — AI Security Proxy

## Overview

The AI Security Proxy is a **transparent gateway** that intercepts all requests
between an application and an LLM provider. It enforces security and privacy
policies through a modular pipeline of detection modules.

## Request Lifecycle

```
Step  1  │  Application sends POST /v1/chat/completions
Step  2  │  FastAPI receives and validates the request
Step  3  │  Generate unique request_id (req_xxxxxxxx)
Step  4  │  Emit REQUEST_RECEIVED event
Step  5  │  Extract user message content
Step  6  │  Run SecurityPipeline (ordered modules)
Step  7  │  Module 1: PII/Secret detection → MODIFY (redact)
Step  8  │  Module 2: Prompt injection check → BLOCK or ALLOW
Step  9  │  Module N: Policy engine → final decision
Step 10  │  If BLOCK → return 403, LLM never contacted
Step 11  │  If ALLOW → sanitized prompt → LLM Router
Step 12  │  LLM Router dispatches to active provider
Step 13  │  Receive LLM response
Step 14  │  Optional: de-tokenize placeholders in response
Step 15  │  Emit REQUEST_COMPLETED event
Step 16  │  Return OpenAI-compatible response to application
```

## SecurityModule Interface

Every detection module must implement this contract:

```python
from app.security.interfaces import SecurityModule, SecurityResult, Decision

class MyModule(SecurityModule):

    @property
    def name(self) -> str:
        return "my-module"

    async def inspect(self, content: str, context: dict) -> SecurityResult:
        # Analyse content...
        return SecurityResult(
            decision=Decision.ALLOW,  # or BLOCK or MODIFY
            module_name=self.name,
            reason="explanation",
            modified_content=None,    # set when MODIFY
            metadata={},              # structured detection data
        )
```

### Decision Enum

| Value | Meaning |
|---|---|
| `ALLOW` | Content is safe — pass through unchanged |
| `BLOCK` | Content is dangerous — reject immediately, LLM never called |
| `MODIFY` | Content has sensitive data — use `modified_content` instead |

### Context Dictionary

The `context` dict passed to every module contains at minimum:

```python
{
    "request_id": "req_a1b2c3d4",
    "user_id": "user_42" or None,
    "model": "gpt-4",
    "detections": [],  # populated by earlier modules
}
```

Modules should append to `context["detections"]` so downstream modules
(especially the PolicyEngine) can make informed decisions.

## SecurityPipeline

The pipeline runs modules **in registration order**:

```
Module 1 (PII)  →  Module 2 (Injection)  →  Module 3 (Policy)
      │                    │                       │
   MODIFY              ALLOW                   ALLOW
      │                    │                       │
   content'            content'                content'
```

- **BLOCK** short-circuits: no subsequent modules run.
- **MODIFY** feeds `modified_content` to the next module.
- **ALLOW** passes content unchanged.

## LLM Router

The router supports multiple providers through the `LLMProvider` ABC:

```python
from app.proxy.router import LLMProvider, LLMResponse

class MyProvider(LLMProvider):
    @property
    def provider_name(self) -> str:
        return "my-provider"

    async def generate(self, model, messages, **kwargs) -> LLMResponse:
        ...
```

Built-in providers:
- **MockProvider** — deterministic responses for testing
- **OpenAIProvider** — OpenAI API
- **GeminiProvider** — Google Gemini API
- **OllamaProvider** — local Ollama instance

## Security Events

The proxy emits structured events for observability:

| Event Type | When |
|---|---|
| `REQUEST_RECEIVED` | Request enters the proxy |
| `PII_DETECTED` | PII found in content |
| `SECRET_DETECTED` | Secret/API key found |
| `PROMPT_INJECTION_DETECTED` | Injection attempt |
| `REQUEST_BLOCKED` | Pipeline blocks the request |
| `REQUEST_SANITIZED` | Content was modified/redacted |
| `LLM_REQUEST` | Forwarding to LLM |
| `LLM_RESPONSE` | Response received from LLM |
| `REQUEST_COMPLETED` | Full lifecycle complete |
| `REQUEST_FAILED` | Error during processing |

**Critical rule:** Events NEVER contain raw sensitive content. Only metadata
(detection type, count, placeholder IDs, timestamps) is logged.

## Policy Engine

The PolicyEngine maps detection types to enforcement actions:

```yaml
policy:
  pii:              redact   # Replace with placeholders
  secrets:          redact
  prompt_injection:  block   # Reject entirely
```

This is configurable via environment variables:
- `POLICY_PII_ACTION`
- `POLICY_SECRETS_ACTION`
- `POLICY_PROMPT_INJECTION_ACTION`
