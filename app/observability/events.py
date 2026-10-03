"""Security event schema and in-memory event emitter.

Events are the bridge between the proxy and the observability dashboard.
Person 4 (dashboard owner) consumes these events.

IMPORTANT: Never log raw sensitive content — only metadata.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.utils.ids import generate_event_id

logger = logging.getLogger(__name__)


# ── Event Types ──────────────────────────────────────────────

class EventType:
    """Constants for security event types."""

    REQUEST_RECEIVED = "REQUEST_RECEIVED"
    PII_DETECTED = "PII_DETECTED"
    SECRET_DETECTED = "SECRET_DETECTED"
    PROMPT_INJECTION_DETECTED = "PROMPT_INJECTION_DETECTED"
    REQUEST_BLOCKED = "REQUEST_BLOCKED"
    REQUEST_SANITIZED = "REQUEST_SANITIZED"
    LLM_REQUEST = "LLM_REQUEST"
    LLM_RESPONSE = "LLM_RESPONSE"
    REQUEST_COMPLETED = "REQUEST_COMPLETED"
    REQUEST_FAILED = "REQUEST_FAILED"


# ── Event Schema ─────────────────────────────────────────────

@dataclass
class SecurityEvent:
    """A single auditable security event.

    Attributes:
        event_id: Unique event identifier.
        request_id: Identifier of the originating request.
        timestamp: ISO-8601 UTC timestamp.
        event_type: One of the EventType constants.
        user_id: Optional user identifier.
        decision: Pipeline decision at this point.
        risk_level: Optional risk classification.
        metadata: Structured metadata (NEVER raw PII).
    """

    event_id: str
    request_id: str
    timestamp: str
    event_type: str
    user_id: Optional[str] = None
    decision: Optional[str] = None
    risk_level: Optional[str] = None
    metadata: dict = field(default_factory=dict)


# ── Emitter ──────────────────────────────────────────────────

class EventEmitter:
    """In-memory event bus.

    Stores events keyed by request_id for later retrieval.
    In production this would publish to a message queue or database.
    """

    def __init__(self) -> None:
        self._events: list[SecurityEvent] = []
        self._by_request: dict[str, list[SecurityEvent]] = {}

    def emit(self, event: SecurityEvent) -> None:
        """Record and log a security event."""
        self._events.append(event)
        self._by_request.setdefault(event.request_id, []).append(event)
        logger.info(
            "SecurityEvent | type=%s request_id=%s decision=%s",
            event.event_type,
            event.request_id,
            event.decision,
        )

    def create_and_emit(
        self,
        *,
        request_id: str,
        event_type: str,
        user_id: Optional[str] = None,
        decision: Optional[str] = None,
        risk_level: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> SecurityEvent:
        """Convenience: build a SecurityEvent and emit it in one call."""
        event = SecurityEvent(
            event_id=generate_event_id(),
            request_id=request_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            user_id=user_id,
            decision=decision,
            risk_level=risk_level,
            metadata=metadata or {},
        )
        self.emit(event)
        return event

    def get_events(self, request_id: str) -> list[SecurityEvent]:
        """Return all events for a given request."""
        return self._by_request.get(request_id, [])

    def get_all_events(self) -> list[SecurityEvent]:
        """Return every recorded event."""
        return list(self._events)

    def get_stats(self) -> dict:
        """Return aggregate statistics for the dashboard."""
        total = len(self._events)
        blocked = sum(
            1 for e in self._events if e.event_type == EventType.REQUEST_BLOCKED
        )
        pii = sum(
            1 for e in self._events if e.event_type == EventType.PII_DETECTED
        )
        secrets = sum(
            1 for e in self._events if e.event_type == EventType.SECRET_DETECTED
        )
        injections = sum(
            1
            for e in self._events
            if e.event_type == EventType.PROMPT_INJECTION_DETECTED
        )
        return {
            "total_events": total,
            "requests_blocked": blocked,
            "pii_detections": pii,
            "secret_detections": secrets,
            "injection_detections": injections,
        }


# ── Singleton ────────────────────────────────────────────────

_emitter: Optional[EventEmitter] = None


def get_event_emitter() -> EventEmitter:
    """Return the global EventEmitter singleton."""
    global _emitter
    if _emitter is None:
        _emitter = EventEmitter()
    return _emitter
