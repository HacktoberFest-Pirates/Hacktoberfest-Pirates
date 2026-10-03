# Integration Guide

The Privacy Engine exposes a stable facade through `PrivacyEngine`.

## Initialization
```python
from app.privacy.engine import create_privacy_engine

# The facade can be created once per application lifecycle or per request
privacy_engine = create_privacy_engine()
```

## Request Workflow
For every user request that requires LLM processing:

```python
request_id = "unique_req_123"
user_id = "user_456"
tenant_id = "tenant_789"
original_text = "Summarize this: email is test@test.com"

try:
    # 1. Sanitize
    sanitized = privacy_engine.sanitize(
        text=original_text,
        request_id=request_id,
        user_id=user_id,
        tenant_id=tenant_id
    )
    
    # 2. Call external LLM
    llm_response_text = call_external_llm(sanitized.sanitized_text)
    
    # 3. Restore
    restored = privacy_engine.restore(
        text=llm_response_text,
        request_id=request_id,
        user_id=user_id,
        tenant_id=tenant_id
    )
    
    final_output = restored.restored_text

finally:
    # 4. Always cleanup vault mapping
    privacy_engine.cleanup(
        request_id=request_id,
        user_id=user_id,
        tenant_id=tenant_id
    )
```

## Safe Metadata for Observability
The returned `SanitizeResponse` and `RestoreResponse` do NOT contain original PII values. You can safely send this metadata to the Observability or Security engine.

```python
safe_metadata = {
    "detected_count": sanitized.detected_entity_count,
    "types": [t.value for t in sanitized.detected_entity_types],
    "restoration_count": restored.restoration_count
}
```
