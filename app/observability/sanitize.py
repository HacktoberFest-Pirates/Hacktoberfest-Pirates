"""Privacy firewall: every event passes through here before it is persisted or logged."""
from __future__ import annotations

import hashlib
import re
from typing import Any

_FORBIDDEN_KEY = re.compile(
    r"^(prompt|messages?|content|text|raw.*|password|passwd|secret.*|api_?key|authorization|auth|"
    r"bearer|credentials?|access_token|refresh_token|token|original.*|value|values|entity|entities_text|"
    r"response_text|completion|body)$",
    re.IGNORECASE,
)
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")),
    ("API_KEY", re.compile(r"\b(?:sk|pk|gsk|AIza|ghp|xox[bap])[-_A-Za-z0-9]{12,}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("PHONE", re.compile(r"\+?\d[\d\s().-]{8,}\d")),
    ("IP_ADDRESS", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("SECRET", re.compile(r"\b[A-Za-z0-9+/_-]{32,}={0,2}\b")),
]
MAX_STR = 200
MAX_DEPTH = 3
MAX_ITEMS = 50


def fingerprint(value: str) -> str:
    """Short one-way fingerprint, useful for correlating without storing content."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def scrub_text(text: str) -> str:
    """Replace anything resembling PII/secrets in a free-text string."""
    for label, pattern in _PATTERNS:
        text = pattern.sub(f"[REDACTED:{label}]", text)
    return text[:MAX_STR]


def sanitize_metadata(data: Any, *, dev_only: bool = False, _depth: int = 0) -> Any:
    """Recursively drop content-bearing keys and scrub string values."""
    if _depth > MAX_DEPTH:
        return "[TRUNCATED]"
    if isinstance(data, dict):
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(data.items()):
            if i >= MAX_ITEMS:
                break
            key = str(k)[:64]
            if not dev_only and _FORBIDDEN_KEY.match(key):
                continue
            out[key] = sanitize_metadata(v, dev_only=dev_only, _depth=_depth + 1)
        return out
    if isinstance(data, (list, tuple, set)):
        return [sanitize_metadata(v, dev_only=dev_only, _depth=_depth + 1) for v in list(data)[:MAX_ITEMS]]
    if isinstance(data, str):
        return scrub_text(data)
    if isinstance(data, (int, float, bool)) or data is None:
        return data
    return scrub_text(str(data))
