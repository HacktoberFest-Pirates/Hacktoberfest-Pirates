"""AI Security Proxy — application entry point.

Starts the FastAPI server and wires up the security pipeline,
LLM router, and observability layer.

Usage:
    uvicorn app.main:app --reload
"""

from __future__ import annotations

import importlib
import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import init_routes, router
from app.config.settings import get_settings
from app.privacy.adapter import PrivacySecurityModule
from app.proxy.pipeline import SecurityPipeline
from app.proxy.router import LLMRouter
from app.proxy.upstream import (
    GeminiProvider,
    MockProvider,
    OllamaProvider,
    OpenAIProvider,
)
from app.security.policy import PolicyEngine
from app.security.prompt_injection import PromptInjectionStubDetector


def _load_extra_modules(spec: str) -> list:
    """Instantiate plug-in security modules from a settings string.

    ``spec`` is a comma-separated list of ``package.module:ClassName``
    entries. Each class is created with no arguments. A bad entry raises at
    startup so a misconfigured security module can never be skipped silently.
    """
    modules = []
    for entry in (part.strip() for part in spec.split(",")):
        if not entry:
            continue
        module_path, _, class_name = entry.partition(":")
        if not module_path or not class_name:
            raise ValueError(
                f"EXTRA_SECURITY_MODULES entry '{entry}' must look like "
                "'package.module:ClassName'"
            )
        cls = getattr(importlib.import_module(module_path), class_name)
        modules.append(cls())
    return modules


def create_app() -> FastAPI:
    """Application factory."""
    settings = get_settings()

    # ── Logging ──────────────────────────────────────────────
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s | %(name)-30s | %(levelname)-7s | %(message)s",
    )
    logger = logging.getLogger(__name__)

    # ── FastAPI ──────────────────────────────────────────────
    application = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "AI Security Proxy — a modular gateway that enforces "
            "privacy and security policies between applications and LLMs."
        ),
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # FastAPI's default 422 body echoes the rejected input back, which can
    # contain secrets. Return only where/why validation failed.
    @application.exception_handler(RequestValidationError)
    async def _safe_validation_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        safe_errors = [
            {
                "loc": list(err.get("loc", [])),
                "msg": err.get("msg"),
                "type": err.get("type"),
            }
            for err in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": safe_errors})

    # ── Security Pipeline ────────────────────────────────────
    detectors: list = []
    if settings.ENABLE_STUB_DETECTORS:
        detectors.append(PrivacySecurityModule())          # Privacy Engine for PII/secret redaction
        detectors.append(PromptInjectionStubDetector())  # Stub injection detector

    # Teammates' modules (set EXTRA_SECURITY_MODULES, no core edits needed)
    detectors.extend(_load_extra_modules(settings.EXTRA_SECURITY_MODULES))

    policy_engine = PolicyEngine()
    pipeline = SecurityPipeline(
        [*detectors, policy_engine],  # Policy enforcement runs last
        fail_closed=settings.SECURITY_FAIL_CLOSED,
        module_timeout_s=settings.SECURITY_MODULE_TIMEOUT_S,
    )
    logger.info(
        "Security pipeline initialised with %d module(s) (fail_closed=%s).",
        len(pipeline.modules),
        settings.SECURITY_FAIL_CLOSED,
    )

    # The privacy engine used for optional de-tokenization is the first
    # module that provides restore() and clear_mapping().
    privacy_engine = next(
        (
            m
            for m in detectors
            if hasattr(m, "restore") and hasattr(m, "clear_mapping")
        ),
        None,
    )

    # ── LLM Router ───────────────────────────────────────────
    llm_router = LLMRouter()

    # Always register mock
    llm_router.register(MockProvider())

    if settings.OPENAI_API_KEY:
        llm_router.register(
            OpenAIProvider(
                api_key=settings.OPENAI_API_KEY,
                base_url=settings.OPENAI_BASE_URL,
            )
        )

    if settings.GEMINI_API_KEY:
        llm_router.register(GeminiProvider(api_key=settings.GEMINI_API_KEY))

    llm_router.register(
        OllamaProvider(base_url=settings.OLLAMA_BASE_URL)
    )

    # Activate the configured provider (fall back to mock)
    active = settings.LLM_PROVIDER
    if settings.MOCK_LLM:
        active = "mock"
    try:
        llm_router.set_active(active)
    except ValueError:
        logger.warning(
            "Provider '%s' not available, falling back to mock.", active
        )
        llm_router.set_active("mock")

    # ── Wire routes ──────────────────────────────────────────
    init_routes(pipeline, llm_router, privacy_engine)
    application.include_router(router); from app.observability.api import router as obs_router; application.include_router(obs_router)

    logger.info(
        "%s v%s ready — provider=%s",
        settings.APP_NAME,
        settings.APP_VERSION,
        llm_router.active_provider.provider_name,
    )

    return application


app = create_app()

