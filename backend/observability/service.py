"""ObservabilityService: the only API other modules need to call."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional, Union

from pydantic import ValidationError

from . import metrics as m
from .config import Settings
from .event_bus import EventBus
from .logger import configure_logging, log_event
from .repository import ObservabilityRepository, QueryFilters
from .sanitize import sanitize_metadata, scrub_text
from .schemas import DEFAULT_SEVERITY, EventType, LLMCall, SecurityEvent, Severity, new_request_id

log = logging.getLogger("observability.service")
MAX_AGG_ROWS = 50_000


class ObservabilityService:
    def __init__(self, settings: Optional[Settings] = None,
                 repository: Optional[ObservabilityRepository] = None, strict: bool = False) -> None:
        self.settings = settings or Settings.from_env()
        configure_logging(self.settings.log_level)
        self.repo = repository or ObservabilityRepository(self.settings.db_url)
        self.strict = strict  # strict=True re-raises validation errors (tests); default never breaks callers
        self.bus = EventBus(async_mode=self.settings.async_writes)
        self.bus.subscribe(self.repo.save_event)
        self.bus.subscribe(log_event)

    # ---------- write side ----------
    def start_request(self, request_id: Optional[str] = None, **metadata: Any) -> str:
        """Create/accept a request_id and emit REQUEST_RECEIVED."""
        rid = request_id or new_request_id()
        self.record_event(EventType.REQUEST_RECEIVED, rid, source="proxy", severity="low", metadata=metadata)
        return rid

    def record_event(self, event_type: Union[EventType, str], request_id: str, source: str = "unknown",
                     severity: Optional[Union[Severity, str]] = None, decision: Optional[str] = None,
                     category: Optional[str] = None, confidence: Optional[float] = None,
                     message: Optional[str] = None, metadata: Optional[dict[str, Any]] = None,
                     timestamp: Optional[datetime] = None) -> Optional[SecurityEvent]:
        """Validate, sanitise and enqueue an event. Returns the event, or None if rejected."""
        try:
            et = EventType(event_type)
            meta = sanitize_metadata(metadata or {}, dev_only=self.settings.development_only_store_content)
            if confidence is None and isinstance(meta.get("confidence"), (int, float)):
                confidence = float(meta["confidence"])
            fields: dict[str, Any] = dict(
                request_id=request_id, event_type=et, source=source,
                severity=Severity(severity) if severity else DEFAULT_SEVERITY.get(et, Severity.LOW),
                decision=decision, category=category, confidence=confidence,
                message=scrub_text(message) if message else None, metadata=meta)
            if timestamp is not None:
                fields["timestamp"] = timestamp
            ev = SecurityEvent(**fields)  # event_id is always generated here
        except (ValidationError, ValueError) as exc:
            log.warning("rejected observability event: %s", type(exc).__name__)
            if self.strict:
                raise
            return None
        self.bus.publish(ev)
        return ev

    record_security_event = record_event

    def record_llm_call(self, request_id: str, provider: str, model: str, prompt_tokens: int = 0,
                        completion_tokens: int = 0, latency_ms: float = 0.0, status: str = "success",
                        estimated_cost: Optional[float] = None, error_type: Optional[str] = None,
                        timestamp: Optional[datetime] = None) -> None:
        """Persist the call and emit LLM_RESPONSE_RECEIVED / LLM_ERROR for the timeline."""
        try:
            extra = {"timestamp": timestamp} if timestamp else {}
            call = LLMCall(request_id=request_id, provider=provider, model=model, **extra,
                           prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                           latency_ms=latency_ms, status=status, estimated_cost=estimated_cost,
                           error_type=error_type)
        except ValidationError as exc:
            log.warning("rejected llm call: %s", type(exc).__name__)
            if self.strict:
                raise
            return
        self.bus.flush()  # ensure the request row/ordering exists before the call row
        self.repo.save_llm_call(call)
        ok = status == "success"
        self.record_event(EventType.LLM_RESPONSE_RECEIVED if ok else EventType.LLM_ERROR, request_id,
                          source="llm_router", severity="low" if ok else "medium",
                          category=None if ok else error_type,
                          timestamp=timestamp,
                          metadata={"provider": provider, "model": model, "total_tokens": call.total_tokens,
                                    "latency_ms": latency_ms, "error_type": error_type})

    def finalize_request(self, request_id: str, status: str = "completed", latency_ms: Optional[float] = None,
                         decision: Optional[str] = None, error_type: Optional[str] = None,
                         timestamp: Optional[datetime] = None) -> None:
        failed = status.lower() == "failed"
        meta: dict[str, Any] = {}
        if latency_ms is not None: meta["latency_ms"] = latency_ms
        if error_type: meta["error_type"] = error_type
        self.record_event(EventType.REQUEST_FAILED if failed else EventType.REQUEST_COMPLETED, request_id,
                          source="proxy", decision=decision, category=error_type, metadata=meta,
                          timestamp=timestamp)

    def flush(self) -> None:
        self.bus.flush()

    # ---------- read side ----------
    def get_request(self, request_id: str) -> Optional[dict[str, Any]]:
        self.flush()
        return self.repo.get_request(request_id)

    def list_requests(self, f: Optional[QueryFilters] = None) -> list[dict[str, Any]]:
        self.flush()
        return self.repo.list_requests(f)

    def list_events(self, f: Optional[QueryFilters] = None) -> list[dict[str, Any]]:
        self.flush()
        return self.repo.get_security_events(f)

    def get_request_timeline(self, request_id: str) -> Optional[dict[str, Any]]:
        self.flush()
        req = self.repo.get_request(request_id)
        if req is None:
            return None
        events = self.repo.get_security_events(QueryFilters(limit=1000), request_id=request_id)
        timeline = [{"event": e["event_type"], "timestamp": e["timestamp"], "severity": e["severity"],
                     "source": e["source"], "decision": e["decision"], "category": e["category"],
                     "confidence": e["confidence"], "metadata": e["metadata"]} for e in events]
        return {"request_id": request_id, "status": req["status"], "decision": req["decision"],
                "request": req, "timeline": timeline}

    def _scoped(self, f: Optional[QueryFilters]) -> QueryFilters:
        f = f or QueryFilters()
        return QueryFilters(**{**f.__dict__, "limit": MAX_AGG_ROWS, "offset": 0})

    def calculate_metrics(self, f: Optional[QueryFilters] = None) -> dict[str, Any]:
        self.flush()
        sf = self._scoped(f)
        out = m.compute_request_metrics(self.repo.list_requests(sf))
        out["llm"] = m.compute_llm_metrics(self.repo.list_llm_calls(sf))
        return out

    def get_security_summary(self, f: Optional[QueryFilters] = None) -> dict[str, Any]:
        self.flush()
        sf = self._scoped(f)
        ef = QueryFilters(**{**sf.__dict__, "model": None, "provider": None, "status": None, "decision": None})
        return m.compute_security_summary(self.repo.list_requests(sf), self.repo.get_security_events(ef))

    def summary(self, f: Optional[QueryFilters] = None) -> dict[str, Any]:
        rm, sec = self.calculate_metrics(f), self.get_security_summary(f)
        return {"total_requests": rm["total_requests"], "blocked_requests": rm["blocked_requests"],
                "pii_detections": sec["pii"]["total_detections"],
                "prompt_injection_detections": sec["prompt_injection"]["total_detections"],
                "avg_latency_ms": rm["avg_latency_ms"], "total_tokens": rm["total_tokens"]}

    def health(self) -> dict[str, Any]:
        db_ok = self.repo.ping()
        return {"status": "ok" if db_ok else "degraded", "database": "ok" if db_ok else "unreachable",
                "dropped_events": self.bus.dropped, "retention_days": self.settings.retention_days,
                "demo_mode": self.settings.demo_mode,
                "content_logging": "DEVELOPMENT_ONLY" if self.settings.development_only_store_content
                else "disabled"}

    def purge_expired(self) -> int:
        return self.repo.purge_older_than(self.settings.retention_days)


# ---------- lazy module-level handle:  from backend.observability.service import observability ----------
_service: Optional[ObservabilityService] = None


def get_service() -> ObservabilityService:
    global _service
    if _service is None:
        _service = ObservabilityService()
    return _service


def set_service(svc: Optional[ObservabilityService]) -> None:
    global _service
    _service = svc


class _LazyHandle:
    def __getattr__(self, name: str) -> Any:
        return getattr(get_service(), name)


observability = _LazyHandle()
