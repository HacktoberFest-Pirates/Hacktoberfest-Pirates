"""Prompt injection detector — DEMO STUB.

This module provides basic pattern-based prompt injection detection so
Person 1's proxy pipeline can be demonstrated end-to-end (Demo 4).
Person 2 / Security teammate will plug in full ML-based detection.

Privacy rule: this module never logs or stores the text it matched. Only the
request id, rule name and pattern source (which is our own regex, not user
content) are recorded.
"""

from __future__ import annotations

import logging
import re

from app.observability.schemas import EventType
from app.observability.service import observability
from app.security.interfaces import Decision, SecurityModule, SecurityResult

logger = logging.getLogger(__name__)

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"override\s+(the\s+)?system\s+prompt", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+in\s+developer\s+mode", re.IGNORECASE),
    re.compile(r"dan\s+mode\s+enabled", re.IGNORECASE),
    re.compile(r"\bjailbreak\b", re.IGNORECASE),
]


class PromptInjectionStubDetector(SecurityModule):
    """Detects prompt injection attempts and flags them for the PolicyEngine.

    Note: Following the pipeline architecture, detectors flag discoveries
    in ``context["detections"]``, allowing the ``PolicyEngine`` to make the
    authoritative BLOCK / ALLOW decision based on configured policy.
    """

    @property
    def name(self) -> str:
        return "prompt-injection-detector"

    async def inspect(self, content: str, context: dict) -> SecurityResult:
        request_id = context.get("request_id", "unknown")
        user_id = context.get("user_id")

        for pattern in _INJECTION_PATTERNS:
            if pattern.search(content):
                # NOTE: do NOT log the matched text — it is user content.
                logger.warning(
                    "Prompt injection detected request_id=%s rule=%s",
                    request_id,
                    "instruction_override",
                )

                # Emit audit event
                
                observability.record_event(EventType.PROMPT_INJECTION_DETECTED, request_id, source=self.name, severity="high", metadata=metadata)

                # Register detection in shared context for PolicyEngine
                context.setdefault("detections", []).append({
                    "type": "prompt_injection",
                    "subtype": "instruction_override",
                    "risk_level": "high",
                })

                return SecurityResult(
                    decision=Decision.ALLOW,
                    module_name=self.name,
                    reason="Suspicious instruction override detected.",
                    metadata={
                        "flagged": True,
                        "detection_type": "prompt_injection",
                    },
                )

        return SecurityResult(
            decision=Decision.ALLOW,
            module_name=self.name,
            reason="No prompt injection patterns detected.",
        )


