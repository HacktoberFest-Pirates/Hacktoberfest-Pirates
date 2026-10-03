"""LLM router — dispatches requests to the configured LLM provider."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Standardized response from any LLM provider.

    Attributes:
        content: The generated text.
        model: Model identifier that actually served the request.
        provider: Provider name (e.g. 'openai', 'ollama').
        usage: Token usage dict with prompt_tokens, completion_tokens, total_tokens.
        raw: The raw provider response for debugging.
    """

    content: str
    model: str
    provider: str
    usage: dict = field(default_factory=lambda: {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
    })
    raw: Optional[Any] = None


class LLMProvider(ABC):
    """Abstract base class for LLM provider implementations.

    Subclass this to add a new provider (OpenAI, Gemini, Ollama, etc.).
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider identifier."""
        ...

    @abstractmethod
    async def generate(
        self,
        model: str,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> LLMResponse:
        """Send a chat-completion request to the provider.

        Args:
            model: Model name requested by the user.
            messages: List of {role, content} dicts.
            **kwargs: Additional provider-specific parameters.

        Returns:
            An LLMResponse.
        """
        ...

    async def health_check(self) -> bool:
        """Return True if the provider is reachable."""
        return True


class LLMRouter:
    """Routes requests to the active LLM provider."""

    def __init__(self) -> None:
        self._providers: dict[str, LLMProvider] = {}
        self._active: Optional[str] = None

    def register(self, provider: LLMProvider) -> None:
        """Register a provider by its name."""
        self._providers[provider.provider_name] = provider
        logger.info("Registered LLM provider: %s", provider.provider_name)

    def set_active(self, name: str) -> None:
        """Set the active provider by name."""
        if name not in self._providers:
            raise ValueError(
                f"Unknown provider '{name}'. "
                f"Registered: {list(self._providers)}"
            )
        self._active = name
        logger.info("Active LLM provider set to: %s", name)

    @property
    def active_provider(self) -> LLMProvider:
        """Return the currently active provider."""
        if self._active is None:
            raise RuntimeError("No active LLM provider configured.")
        return self._providers[self._active]

    async def generate(
        self,
        model: str,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> LLMResponse:
        """Forward the request to the active provider."""
        provider = self.active_provider
        return await provider.generate(model, messages, **kwargs)

    async def health_check(self) -> dict:
        """Check health of all registered providers."""
        results = {}
        for name, provider in self._providers.items():
            try:
                results[name] = await provider.health_check()
            except Exception:
                results[name] = False
        return results
