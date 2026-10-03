"""Policy engine — maps detection results to enforcement decisions.

Instead of hard-coding BLOCK/ALLOW throughout the codebase, the policy
engine centralises decision-making so behaviour can be changed via
configuration alone.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.config.settings import get_settings
from app.security.interfaces import Decision, SecurityModule, SecurityResult

logger = logging.getLogger(__name__)


class PolicyEngine(SecurityModule):
    """Evaluates aggregated detection metadata against the configured policy.

    The PolicyEngine is typically the *last* module in the pipeline. It
    inspects the context (populated by earlier modules) and issues a
    final BLOCK if any detection type exceeds its policy threshold.
    """

    def __init__(
        self,
        *,
        pii_action: Optional[str] = None,
        secrets_action: Optional[str] = None,
        prompt_injection_action: Optional[str] = None,
    ) -> None:
        settings = get_settings()
        self._policy = {
            "pii": pii_action or settings.POLICY_PII_ACTION,
            "secrets": secrets_action or settings.POLICY_SECRETS_ACTION,
            "prompt_injection": (
                prompt_injection_action
                or settings.POLICY_PROMPT_INJECTION_ACTION
            ),
        }
        logger.info("PolicyEngine initialised with policy: %s", self._policy)

    @property
    def name(self) -> str:
        return "policy-engine"

    async def inspect(self, content: str, context: dict) -> SecurityResult:
        """Check accumulated detections against policy rules.

        The policy engine reads 'detections' from context, which earlier
        modules should populate:

            context["detections"] = [
                {"type": "pii", "subtype": "email", ...},
                {"type": "prompt_injection", ...},
            ]
        """
        detections = context.get("detections", [])

        if not detections:
            return SecurityResult(
                decision=Decision.ALLOW,
                module_name=self.name,
                reason="No detections to evaluate.",
            )

        # Check each detection type against the policy
        for detection in detections:
            det_type = detection.get("type", "unknown")
            action = self._policy.get(det_type, "allow")

            if action == "block":
                return SecurityResult(
                    decision=Decision.BLOCK,
                    module_name=self.name,
                    reason=(
                        f"Policy blocks '{det_type}' detections. "
                        f"Detection: {detection.get('subtype', det_type)}"
                    ),
                    metadata={"blocked_detection": detection},
                )

        return SecurityResult(
            decision=Decision.ALLOW,
            module_name=self.name,
            reason="All detections within policy.",
            metadata={"policy": self._policy, "detection_count": len(detections)},
        )

    def get_policy(self) -> dict:
        """Return the current policy configuration."""
        return dict(self._policy)
