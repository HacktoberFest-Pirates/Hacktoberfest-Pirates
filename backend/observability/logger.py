"""Structured (JSON) logging of already-sanitised events."""
from __future__ import annotations

import json
import logging

from .schemas import SecurityEvent

_logger = logging.getLogger("observability.events")


def configure_logging(level: str = "INFO") -> None:
    _logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not _logger.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(message)s"))
        _logger.addHandler(h)
        _logger.propagate = False


def log_event(ev: SecurityEvent) -> None:
    """Emit one JSON line. Payload is sanitised upstream; never include raw content here."""
    level = logging.WARNING if ev.severity.value in {"high", "critical"} else logging.INFO
    if _logger.isEnabledFor(level):
        _logger.log(level, json.dumps({
            "ts": ev.timestamp.isoformat() + "Z", "request_id": ev.request_id,
            "event_type": ev.event_type.value, "source": ev.source, "severity": ev.severity.value,
            "decision": ev.decision, "category": ev.category, "confidence": ev.confidence,
            "metadata": ev.metadata}, default=str))
