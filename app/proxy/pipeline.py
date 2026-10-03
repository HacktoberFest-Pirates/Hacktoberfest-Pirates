"""Security pipeline — orchestrates all security modules in sequence.

This is the heart of the proxy. It runs each registered SecurityModule
in order, accumulates results, and produces a final decision.

Failure handling
----------------
If a module raises or exceeds ``module_timeout_s``:
  * ``fail_closed=False`` (default, MVP behaviour): the module is treated
    as ALLOW and the pipeline continues.
  * ``fail_closed=True``: the module is treated as BLOCK and the pipeline
    stops (the LLM is never contacted).
Only the exception *type* is logged/recorded, never its message, because an
exception message can contain fragments of the prompt.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from app.security.interfaces import Decision, SecurityModule, SecurityResult
from app.observability.schemas import EventType
from app.observability.service import observability

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Aggregated result from the full security pipeline.

    Attributes:
        decision: Final pipeline verdict.
        content: Sanitized content (None when blocked).
        results: Individual module results in execution order.
        duration_ms: Total pipeline processing time.
    """

    decision: Decision
    content: Optional[str] = None
    results: list[SecurityResult] = field(default_factory=list)
    duration_ms: float = 0.0


class SecurityPipeline:
    """Runs an ordered chain of SecurityModules against request content.

    Usage::

        pipeline = SecurityPipeline([
            PlaceholderPIIDetector(),
            PromptInjectionDetector(),
            # ... more modules
        ])
        result = await pipeline.process(content, context)

    Note: ``process`` is called once per user message, so modules must
    tolerate several calls that share the same ``context["request_id"]``.
    """

    def __init__(
        self,
        modules: list[SecurityModule] | None = None,
        *,
        fail_closed: bool = False,
        module_timeout_s: float | None = None,
    ) -> None:
        self.modules: list[SecurityModule] = modules or []
        self.fail_closed = fail_closed
        # 0 / None means "no timeout".
        self.module_timeout_s = module_timeout_s if module_timeout_s else None

    def register(self, module: SecurityModule) -> None:
        """Append a module to the pipeline."""
        logger.info("Registered security module: %s", module.name)
        self.modules.append(module)

    async def _run_module(
        self, module: SecurityModule, content: str, context: dict
    ) -> SecurityResult:
        """Run one module, converting crashes/timeouts into a safe result."""
        try:
            if self.module_timeout_s:
                return await asyncio.wait_for(
                    module.inspect(content, context),
                    timeout=self.module_timeout_s,
                )
            return await module.inspect(content, context)
        except Exception as exc:  # noqa: BLE001 - isolate any module failure
            error_type = type(exc).__name__
            logger.error(
                "Security module failed module=%s error_type=%s fail_closed=%s",
                module.name,
                error_type,
                self.fail_closed,
            )
            return SecurityResult(
                decision=Decision.BLOCK if self.fail_closed else Decision.ALLOW,
                module_name=module.name,
                reason=f"Module error: {error_type}",
                metadata={
                    "error": True,
                    "error_type": error_type,
                    "fail_closed": self.fail_closed,
                },
            )

    async def process(
        self, content: str, context: dict
    ) -> PipelineResult:
        """Run all modules against *content* in registration order.

        Args:
            content: The raw user prompt text.
            context: Request metadata (request_id, user_id, …).

        Returns:
            A PipelineResult with the final verdict and (optionally)
            sanitized content.
        """
        
        request_id = context.get("request_id", "unknown")
        start = time.perf_counter()

        current_content = content
        results: list[SecurityResult] = []

        for module in self.modules:
            result = await self._run_module(module, current_content, context)
            results.append(result)

            # ── BLOCK: short-circuit immediately ─────────────
            if result.decision == Decision.BLOCK:
                observability.record_event(EventType.REQUEST_BLOCKED, request_id, source=module.name, decision="block", severity="high", metadata={
                        "blocked_by": module.name,
                        "reason": result.reason,
                    })
                elapsed = (time.perf_counter() - start) * 1000
                return PipelineResult(
                    decision=Decision.BLOCK,
                    content=None,
                    results=results,
                    duration_ms=round(elapsed, 2),
                )

            # ── MODIFY: feed sanitized text downstream ───────
            if result.decision == Decision.MODIFY and result.modified_content:
                current_content = result.modified_content
                observability.record_event(EventType.RESPONSE_SANITIZED, request_id, source=module.name, decision="modify", metadata={
                        "module": module.name,
                        "reason": result.reason,
                    })

        elapsed = (time.perf_counter() - start) * 1000
        return PipelineResult(
            decision=Decision.ALLOW,
            content=current_content,
            results=results,
            duration_ms=round(elapsed, 2),
        )

