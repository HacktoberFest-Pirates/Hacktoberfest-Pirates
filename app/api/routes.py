"""FastAPI route handlers for the AI Security Proxy."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException

from app.api.schemas import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    Choice,
    HealthResponse,
    Message,
    ReadyResponse,
    Usage,
)
from app.config.settings import get_settings
from app.observability.events import EventType, get_event_emitter
from app.proxy.pipeline import SecurityPipeline
from app.proxy.router import LLMRouter
from app.security.interfaces import Decision
from app.utils.ids import generate_request_id

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Module-level references (set during app startup) ────────
_pipeline: SecurityPipeline | None = None
_llm_router: LLMRouter | None = None
# Optional privacy engine used for de-tokenization. Any object exposing
#   restore(request_id, text) -> str   and   clear_mapping(request_id) -> None
_placeholder_detector: Any = None


def init_routes(
    pipeline: SecurityPipeline,
    llm_router: LLMRouter,
    placeholder_detector: Any = None,
) -> None:
    """Inject runtime dependencies into the route handlers."""
    global _pipeline, _llm_router, _placeholder_detector
    _pipeline = pipeline
    _llm_router = llm_router
    _placeholder_detector = placeholder_detector


# ── Health & Readiness ───────────────────────────────────────

@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Liveness probe."""
    settings = get_settings()
    return HealthResponse(
        status="healthy",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
    )


@router.get("/ready", response_model=ReadyResponse)
async def ready() -> ReadyResponse:
    """Readiness probe — verifies subsystems."""
    checks: dict[str, bool] = {
        "pipeline": _pipeline is not None and len(_pipeline.modules) >= 0,
        "llm_router": _llm_router is not None,
    }

    if _llm_router:
        try:
            provider_checks = await _llm_router.health_check()
            checks["llm_providers"] = any(provider_checks.values())
        except Exception:
            checks["llm_providers"] = False

    overall = all(checks.values())
    return ReadyResponse(
        status="ready" if overall else "degraded",
        checks=checks,
    )


# ── Observability ────────────────────────────────────────────

@router.get("/v1/stats")
async def stats() -> dict:
    """Return aggregate security statistics for the dashboard."""
    emitter = get_event_emitter()
    return emitter.get_stats()


@router.get("/v1/events/{request_id}")
async def get_events(request_id: str) -> list[dict]:
    """Return all security events for a given request."""
    emitter = get_event_emitter()
    events = emitter.get_events(request_id)
    return [
        {
            "event_id": e.event_id,
            "event_type": e.event_type,
            "timestamp": e.timestamp,
            "decision": e.decision,
            "risk_level": e.risk_level,
            "metadata": e.metadata,
        }
        for e in events
    ]


# ── Chat Completion ──────────────────────────────────────────

@router.post("/v1/chat/completions", response_model=ChatCompletionResponse)
async def chat_completions(
    request: ChatCompletionRequest,
    x_restore_placeholders: Optional[str] = Header(
        default=None, alias="x-restore-placeholders"
    ),
) -> ChatCompletionResponse:
    """OpenAI-compatible chat completion endpoint with security pipeline.

    Privacy rules enforced here:
      * raw prompt/response text is never logged or put in events/errors;
      * only exception *types* are recorded, never exception messages;
      * the per-request placeholder mapping is always cleared, whether the
        request succeeds, is blocked, or fails.
    """
    if _pipeline is None or _llm_router is None:
        raise HTTPException(status_code=503, detail="Proxy not initialised.")

    request_id = generate_request_id()
    emitter = get_event_emitter()
    settings = get_settings()
    start_time = time.perf_counter()

    # ── Step 1: Emit REQUEST_RECEIVED ────────────────────────
    emitter.create_and_emit(
        request_id=request_id,
        event_type=EventType.REQUEST_RECEIVED,
        user_id=request.user,
        metadata={"model": request.model, "message_count": len(request.messages)},
    )

    context: dict[str, Any] = {
        "request_id": request_id,
        "user_id": request.user,
        "model": request.model,
        "detections": [],
    }

    try:
        # ── Step 2/3: Run the pipeline on each user message ──
        # Each user message is inspected separately so multi-turn
        # conversations keep their structure.
        sanitized_messages: list[dict[str, str]] = []
        pipeline_ms = 0.0
        redactions = 0

        for msg in request.messages:
            if msg.role != "user":
                sanitized_messages.append(
                    {"role": msg.role, "content": msg.content}
                )
                continue

            pipeline_result = await _pipeline.process(msg.content, context)
            pipeline_ms += pipeline_result.duration_ms

            if pipeline_result.decision == Decision.BLOCK:
                blocked_reasons = [
                    r.reason
                    for r in pipeline_result.results
                    if r.decision == Decision.BLOCK
                ]
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "Request blocked by security policy.",
                        "request_id": request_id,
                        "reasons": blocked_reasons,
                    },
                )

            redactions += sum(
                1
                for r in pipeline_result.results
                if r.decision == Decision.MODIFY
            )
            sanitized_messages.append(
                {
                    "role": msg.role,
                    "content": (
                        pipeline_result.content
                        if pipeline_result.content is not None
                        else msg.content
                    ),
                }
            )

        # ── Step 4: Call LLM ─────────────────────────────────
        emitter.create_and_emit(
            request_id=request_id,
            event_type=EventType.LLM_REQUEST,
            user_id=request.user,
            metadata={"provider": _llm_router.active_provider.provider_name},
        )

        try:
            generate_call = _llm_router.generate(
                model=request.model,
                messages=sanitized_messages,
                temperature=request.temperature,
                max_tokens=request.max_tokens,
            )
            if settings.LLM_TIMEOUT_S and settings.LLM_TIMEOUT_S > 0:
                llm_response = await asyncio.wait_for(
                    generate_call, timeout=settings.LLM_TIMEOUT_S
                )
            else:
                llm_response = await generate_call
        except asyncio.TimeoutError:
            emitter.create_and_emit(
                request_id=request_id,
                event_type=EventType.REQUEST_FAILED,
                user_id=request.user,
                metadata={"error_type": "TimeoutError"},
            )
            raise HTTPException(
                status_code=504,
                detail={
                    "error": "LLM provider timed out.",
                    "request_id": request_id,
                },
            ) from None
        except Exception as exc:
            # Never record str(exc): provider errors can contain URLs with
            # API keys or fragments of the request.
            emitter.create_and_emit(
                request_id=request_id,
                event_type=EventType.REQUEST_FAILED,
                user_id=request.user,
                metadata={"error_type": type(exc).__name__},
            )
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "LLM provider error.",
                    "request_id": request_id,
                },
            ) from None

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        emitter.create_and_emit(
            request_id=request_id,
            event_type=EventType.LLM_RESPONSE,
            user_id=request.user,
            metadata={
                "provider": llm_response.provider,
                "latency_ms": latency_ms,
                "usage": llm_response.usage,
            },
        )

        # ── Step 5: Optional de-tokenization ─────────────────
        # Restored text goes only into the HTTP response body; it is never
        # logged or attached to an event.
        response_content = llm_response.content
        restore_requested = (
            x_restore_placeholders.lower() in ("true", "1")
            if x_restore_placeholders
            else settings.RESTORE_PLACEHOLDERS
        )
        if _placeholder_detector is not None and restore_requested:
            response_content = _placeholder_detector.restore(
                request_id, response_content
            )

        # ── Step 6: Emit REQUEST_COMPLETED ───────────────────
        emitter.create_and_emit(
            request_id=request_id,
            event_type=EventType.REQUEST_COMPLETED,
            user_id=request.user,
            decision="allow",
            metadata={
                "latency_ms": latency_ms,
                "pipeline_ms": round(pipeline_ms, 2),
                "redactions": redactions,
            },
        )

        # ── Step 7: Return OpenAI-compatible response ────────
        return ChatCompletionResponse(
            id=request_id,
            model=llm_response.model,
            choices=[
                Choice(
                    index=0,
                    message=Message(
                        role="assistant",
                        content=response_content,
                    ),
                )
            ],
            usage=Usage(
                prompt_tokens=llm_response.usage.get("prompt_tokens", 0),
                completion_tokens=llm_response.usage.get("completion_tokens", 0),
                total_tokens=llm_response.usage.get("total_tokens", 0),
            ),
        )

    except HTTPException:
        # Already a deliberate, safe response (403 / 502 / 504).
        raise
    except Exception as exc:
        error_type = type(exc).__name__
        logger.error(
            "Unhandled proxy error request_id=%s error_type=%s",
            request_id,
            error_type,
        )
        emitter.create_and_emit(
            request_id=request_id,
            event_type=EventType.REQUEST_FAILED,
            user_id=request.user,
            metadata={"error_type": error_type},
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal proxy error.",
                "request_id": request_id,
            },
        ) from None
    finally:
        # Always drop the token -> original-value mapping, even on
        # block / failure, so raw values never linger in memory.
        if _placeholder_detector is not None:
            _placeholder_detector.clear_mapping(request_id)
