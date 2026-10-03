"""Standard event model shared by all modules."""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventType(str, Enum):
    REQUEST_RECEIVED = "REQUEST_RECEIVED"
    PII_DETECTED = "PII_DETECTED"
    SENSITIVE_DATA_REDACTED = "SENSITIVE_DATA_REDACTED"
    PLACEHOLDER_CREATED = "PLACEHOLDER_CREATED"
    PLACEHOLDER_RESTORED = "PLACEHOLDER_RESTORED"
    PROMPT_INJECTION_CHECK = "PROMPT_INJECTION_CHECK"
    PROMPT_INJECTION_DETECTED = "PROMPT_INJECTION_DETECTED"
    REQUEST_BLOCKED = "REQUEST_BLOCKED"
    REQUEST_ALLOWED = "REQUEST_ALLOWED"
    LLM_REQUEST_SENT = "LLM_REQUEST_SENT"
    LLM_RESPONSE_RECEIVED = "LLM_RESPONSE_RECEIVED"
    LLM_ERROR = "LLM_ERROR"
    RESPONSE_SANITIZED = "RESPONSE_SANITIZED"
    REQUEST_COMPLETED = "REQUEST_COMPLETED"
    REQUEST_FAILED = "REQUEST_FAILED"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

DEFAULT_SEVERITY: dict[EventType, Severity] = {
    EventType.PII_DETECTED: Severity.MEDIUM,
    EventType.PROMPT_INJECTION_DETECTED: Severity.HIGH,
    EventType.REQUEST_BLOCKED: Severity.HIGH,
    EventType.REQUEST_FAILED: Severity.MEDIUM,
    EventType.LLM_ERROR: Severity.MEDIUM,
}


def new_request_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)  # naive UTC, stored as-is


class SecurityEvent(BaseModel):
    """Validated event. `event_id` is always server-generated (client values are ignored)."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str
    timestamp: datetime = Field(default_factory=utcnow)
    event_type: EventType
    source: str = Field(default="unknown", max_length=64)
    severity: Severity = Severity.LOW
    decision: Optional[str] = Field(default=None, max_length=32)
    category: Optional[str] = Field(default=None, max_length=64)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    message: Optional[str] = Field(default=None, max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("request_id")
    @classmethod
    def _valid_request_id(cls, v: str) -> str:
        if not v or not _ID_RE.match(v):
            raise ValueError("request_id must be 1-64 chars of [A-Za-z0-9_-]")
        return v

    @field_validator("decision", "category")
    @classmethod
    def _upper(cls, v: Optional[str]) -> Optional[str]:
        return v.strip().upper() if v else v

    @field_validator("timestamp")
    @classmethod
    def _naive_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is not None:
            v = v.astimezone(timezone.utc).replace(tzinfo=None)
        return v


class LLMCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    timestamp: datetime = Field(default_factory=utcnow)
    provider: str = Field(max_length=64)
    model: str = Field(max_length=128)
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    latency_ms: float = Field(default=0.0, ge=0)
    status: str = Field(default="success", max_length=32)
    estimated_cost: Optional[float] = Field(default=None, ge=0)
    error_type: Optional[str] = Field(default=None, max_length=64)

    @field_validator("request_id")
    @classmethod
    def _valid_request_id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("invalid request_id")
        return v

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens
