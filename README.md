# AI Security Proxy - Observability & Audit (Person 3)

Records, aggregates and visualises everything the proxy does - **without ever storing raw prompts or PII**.

```
Security modules ──events──▶ ObservabilityService ──▶ SQLite ──▶ Observability API (read-only) ──▶ Streamlit
                              (validate+sanitise)      (SQLAlchemy)     /observability/*                (presentation only)
```

## Layout
`backend/observability/` schemas · sanitize · event_bus · logger · repository · metrics · service · api · demo  
`dashboard/` app.py · api_client.py · metrics.py · components/  
`scripts/generate_demo_events.py` · `tests/observability/` · `docs/observability-integration.md`

## Quick start
```bash
pip install -r requirements.txt
cp .env.example .env            # optional; export vars or use your env loader
python scripts/generate_demo_events.py --reset      # creates ./observability.db (tables auto-created)
uvicorn backend.observability.api:app --port 8001   # or include the router in the main app
streamlit run dashboard/app.py                      # http://localhost:8501
pytest                                              # 32 tests
```

## Event schema
`event_id, request_id, timestamp, event_type, source, severity, decision, category, confidence, message, metadata` -
see `docs/observability-integration.md` for emit snippets for each team member.

## Database (SQLite via SQLAlchemy; swap with `OBSERVABILITY_DB_URL`)
- `requests(request_id PK, timestamp, status, decision, model, provider, latency_ms, prompt/completion/total_tokens, pii_count, placeholder_count, injection_detected, error_type)`
- `security_events(seq, event_id UNIQUE, request_id FK, timestamp, event_type, severity, source, category, confidence, decision, message, metadata_json)`
- `llm_calls(id, request_id FK, timestamp, provider, model, prompt/completion/total_tokens, latency_ms, status, estimated_cost, error_type)`

## API (read-only; filters: `limit, offset, start_time, end_time, event_type, severity, decision, model, provider, status`)
`GET /observability/summary | /requests | /requests/{id} (timeline) | /events | /security | /metrics | /health`

```json
GET /observability/summary
{"total_requests":150,"blocked_requests":14,"pii_detections":189,"prompt_injection_detections":22,"avg_latency_ms":1010.92,"total_tokens":157487}
```

## Privacy guarantees
Counts/categories/decisions/ids only. Content-bearing keys are dropped and PII-like strings scrubbed before
persistence or logging; events are validated (strict enum/severity/id format); event IDs are server-generated;
all SQL is ORM-parameterised; the dashboard has a second display filter. `OBSERVABILITY_DEVELOPMENT_ONLY_STORE_CONTENT`
exists for local debugging only and is reported by `/observability/health`.

## Retention
`OBSERVABILITY_RETENTION_DAYS` (default 7). Call `get_service().purge_expired()` (e.g. on startup or from a cron/scheduler).
