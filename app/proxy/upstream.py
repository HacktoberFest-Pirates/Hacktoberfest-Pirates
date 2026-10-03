"""Concrete LLM provider implementations.

Includes:
- MockProvider   — deterministic responses for testing / demo
- OpenAIProvider  — forwards to the OpenAI API
- GeminiProvider  — forwards to the Google Gemini API
- OllamaProvider  — forwards to a local Ollama instance
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.proxy.router import LLMProvider, LLMResponse

logger = logging.getLogger(__name__)


# ── Mock Provider ────────────────────────────────────────────

class MockProvider(LLMProvider):
    """Returns canned responses — perfect for local dev and CI."""

    @property
    def provider_name(self) -> str:
        return "mock"

    async def generate(
        self,
        model: str,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> LLMResponse:
        last_user_msg = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                last_user_msg = msg.get("content", "")
                break

        reply = (
            f"[MOCK] This is a simulated response to: "
            f"{last_user_msg[:80]}{'...' if len(last_user_msg) > 80 else ''}"
        )

        prompt_tokens = sum(len(m.get("content", "").split()) for m in messages)
        completion_tokens = len(reply.split())

        return LLMResponse(
            content=reply,
            model=model,
            provider=self.provider_name,
            usage={
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        )


# ── OpenAI Provider ──────────────────────────────────────────

class OpenAIProvider(LLMProvider):
    """Forwards chat-completion requests to the OpenAI API."""

    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1") -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    @property
    def provider_name(self) -> str:
        return "openai"

    async def generate(
        self,
        model: str,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> LLMResponse:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {"model": model, "messages": messages, **kwargs}

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()

        choice = data["choices"][0]
        usage = data.get("usage", {})

        return LLMResponse(
            content=choice["message"]["content"],
            model=data.get("model", model),
            provider=self.provider_name,
            usage={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
            raw=data,
        )

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                return resp.status_code == 200
        except Exception:
            return False


# ── Gemini Provider ──────────────────────────────────────────

class GeminiProvider(LLMProvider):
    """Forwards requests to the Google Gemini (Generative AI) API."""

    BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    @property
    def provider_name(self) -> str:
        return "gemini"

    async def generate(
        self,
        model: str,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> LLMResponse:
        # Convert OpenAI-style messages to Gemini format
        contents = []
        for msg in messages:
            role = "user" if msg["role"] == "user" else "model"
            contents.append({
                "role": role,
                "parts": [{"text": msg["content"]}],
            })

        url = (
            f"{self.BASE_URL}/models/{model}:generateContent"
            f"?key={self.api_key}"
        )
        payload = {"contents": contents}

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()

        text = (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        )
        usage_meta = data.get("usageMetadata", {})

        return LLMResponse(
            content=text,
            model=model,
            provider=self.provider_name,
            usage={
                "prompt_tokens": usage_meta.get("promptTokenCount", 0),
                "completion_tokens": usage_meta.get("candidatesTokenCount", 0),
                "total_tokens": usage_meta.get("totalTokenCount", 0),
            },
            raw=data,
        )

    async def health_check(self) -> bool:
        try:
            url = f"{self.BASE_URL}/models?key={self.api_key}"
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
                return resp.status_code == 200
        except Exception:
            return False


# ── Ollama Provider ──────────────────────────────────────────

class OllamaProvider(LLMProvider):
    """Forwards requests to a local Ollama instance."""

    def __init__(self, base_url: str = "http://localhost:11434") -> None:
        self.base_url = base_url.rstrip("/")

    @property
    def provider_name(self) -> str:
        return "ollama"

    async def generate(
        self,
        model: str,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> LLMResponse:
        url = f"{self.base_url}/api/chat"
        payload = {"model": model, "messages": messages, "stream": False}

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()

        return LLMResponse(
            content=data.get("message", {}).get("content", ""),
            model=model,
            provider=self.provider_name,
            usage={
                "prompt_tokens": data.get("prompt_eval_count", 0),
                "completion_tokens": data.get("eval_count", 0),
                "total_tokens": (
                    data.get("prompt_eval_count", 0)
                    + data.get("eval_count", 0)
                ),
            },
            raw=data,
        )

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False
