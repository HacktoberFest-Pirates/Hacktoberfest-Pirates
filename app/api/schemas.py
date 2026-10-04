"""Request / response schemas — OpenAI-compatible chat completion API."""

from typing import Optional

from pydantic import BaseModel, Field


# ── Request ──────────────────────────────────────────────────

class Message(BaseModel):
    """A single chat message."""
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    """OpenAI-compatible chat completion request."""
    model: str
    messages: list[Message]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = None
    user: Optional[str] = None


# ── Response ─────────────────────────────────────────────────

class Choice(BaseModel):
    """A single completion choice."""
    index: int = 0
    message: Message
    finish_reason: str = "stop"


class Usage(BaseModel):
    """Token usage statistics."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatCompletionResponse(BaseModel):
    """OpenAI-compatible chat completion response."""
    id: str
    object: str = "chat.completion"
    model: str
    choices: list[Choice]
    usage: Usage = Field(default_factory=Usage)
    debug_sanitized_prompt: Optional[str] = None


# ── Health / Readiness ───────────────────────────────────────

class HealthResponse(BaseModel):
    """Liveness probe response."""
    status: str
    service: str
    version: str


class ReadyResponse(BaseModel):
    """Readiness probe response with subsystem checks."""
    status: str
    checks: dict

