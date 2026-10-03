"""Security module interface — the contract every teammate implements.

This is the most critical file in the project. All security detection
modules (PII, prompt injection, secrets, canary, etc.) MUST implement
the SecurityModule ABC defined here.

Teammates: implement your detector by subclassing SecurityModule and
returning a SecurityResult from inspect().
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Decision(str, Enum):
    """Pipeline decision after a security module runs."""

    ALLOW = "allow"    # Content is safe — pass through unchanged.
    BLOCK = "block"    # Content is dangerous — reject immediately.
    MODIFY = "modify"  # Content has sensitive data — use modified_content.


@dataclass
class SecurityResult:
    """Result returned by every security module.

    Attributes:
        decision: The module's verdict.
        module_name: Name of the module that produced this result.
        reason: Human-readable explanation (never contains raw PII).
        modified_content: Sanitized content when decision is MODIFY.
        metadata: Extra structured data (detection counts, types, etc.).
    """

    decision: Decision
    module_name: str
    reason: Optional[str] = None
    modified_content: Optional[str] = None
    metadata: dict = field(default_factory=dict)


class SecurityModule(ABC):
    """Abstract base class that every security detector must implement.

    Example::

        class MyPIIDetector(SecurityModule):

            @property
            def name(self) -> str:
                return "pii-detector"

            async def inspect(self, content, context):
                # ... detection logic ...
                return SecurityResult(
                    decision=Decision.MODIFY,
                    module_name=self.name,
                    modified_content=sanitized,
                    metadata={"detected": ["email", "phone"]},
                )
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this module (e.g. 'pii-detector')."""
        ...

    @abstractmethod
    async def inspect(self, content: str, context: dict) -> SecurityResult:
        """Inspect content and return a security decision.

        Args:
            content: The text to inspect (may already be partially
                     modified by an earlier module in the pipeline).
            context: Request metadata — at minimum contains
                     ``request_id`` and ``user_id``.

        Returns:
            A SecurityResult with the module's verdict.
        """
        ...
