"""Placeholder PII/secret detector — DEMO STUB.

This module provides basic regex-based detection so Person 1's
pipeline can be demoed end-to-end. Person 2/3 will replace this
with ML-based detection.

Detects:
- Email addresses
- Phone numbers (10+ digits)
- API keys / secrets (sk-*, key-*, etc.)

Contract for a replacement privacy module (used for optional de-tokenization):
    restore(request_id: str, text: str) -> str
    clear_mapping(request_id: str) -> None
``inspect`` may be called several times for one request_id (once per user
message), so token numbering continues and mappings are merged, not replaced.
"""

from __future__ import annotations

import re
from app.observability.events import EventType, get_event_emitter
from app.security.interfaces import Decision, SecurityModule, SecurityResult


# ── Patterns ─────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_PHONE_RE = re.compile(r"\b\d{10,13}\b")
_SECRET_RE = re.compile(
    r"\b(?:sk-|key-|api[_-]?key|secret[_-]?key|token)[a-zA-Z0-9_-]{6,}\b",
    re.IGNORECASE,
)


class PlaceholderDetector(SecurityModule):
    """Regex-based PII/secret stub that replaces matches with tokens.

    Maintains a mapping so responses can optionally be de-tokenized.
    """

    def __init__(self) -> None:
        # Per-request mapping: token -> original value
        self._mappings: dict[str, dict[str, str]] = {}

    @property
    def name(self) -> str:
        return "placeholder-detector"

    async def inspect(self, content: str, context: dict) -> SecurityResult:
        request_id = context.get("request_id", "unknown")
        mapping: dict[str, str] = {}
        counters: dict[str, int] = {"email": 0, "phone": 0, "secret": 0}
        detections: list[dict] = []
        modified = content

        # Continue numbering if this request was already inspected
        # (e.g. an earlier user message), so tokens never collide.
        existing = self._mappings.get(request_id, {})
        offsets = {
            "email": sum(1 for t in existing if t.startswith("<EMAIL_")),
            "phone": sum(1 for t in existing if t.startswith("<PHONE_")),
            "secret": sum(1 for t in existing if t.startswith("<SECRET_")),
        }

        # ── Emails ───────────────────────────────────────────
        for match in _EMAIL_RE.finditer(modified):
            counters["email"] += 1
            token = f"<EMAIL_{offsets['email'] + counters['email']:03d}>"
            mapping[token] = match.group()
            modified = modified.replace(match.group(), token, 1)
            detections.append({"type": "pii", "subtype": "email"})

        # ── Phone numbers ────────────────────────────────────
        for match in _PHONE_RE.finditer(modified):
            counters["phone"] += 1
            token = f"<PHONE_{offsets['phone'] + counters['phone']:03d}>"
            mapping[token] = match.group()
            modified = modified.replace(match.group(), token, 1)
            detections.append({"type": "pii", "subtype": "phone"})

        # ── Secrets / API keys ───────────────────────────────
        for match in _SECRET_RE.finditer(modified):
            counters["secret"] += 1
            token = f"<SECRET_{offsets['secret'] + counters['secret']:03d}>"
            mapping[token] = match.group()
            modified = modified.replace(match.group(), token, 1)
            detections.append({"type": "secrets", "subtype": "api_key"})

        # Store mapping for later de-tokenization
        if mapping:
            self._mappings.setdefault(request_id, {}).update(mapping)
            context.setdefault("detections", []).extend(detections)

            # Emit safe telemetry events (never log raw sensitive values)
            emitter = get_event_emitter()
            user_id = context.get("user_id")

            pii_count = counters["email"] + counters["phone"]
            if pii_count > 0:
                emitter.create_and_emit(
                    request_id=request_id,
                    event_type=EventType.PII_DETECTED,
                    user_id=user_id,
                    decision="modify",
                    metadata={
                        "pii_count": pii_count,
                        "types": {
                            k: v for k, v in counters.items() if k in ("email", "phone") and v > 0
                        },
                    },
                )

            if counters["secret"] > 0:
                emitter.create_and_emit(
                    request_id=request_id,
                    event_type=EventType.SECRET_DETECTED,
                    user_id=user_id,
                    decision="modify",
                    metadata={
                        "secret_count": counters["secret"],
                        "subtype": "api_key",
                    },
                )

            return SecurityResult(
                decision=Decision.MODIFY,
                module_name=self.name,
                reason=f"Redacted {sum(counters.values())} sensitive item(s).",
                modified_content=modified,
                metadata={
                    "redaction_count": sum(counters.values()),
                    "types": {
                        k: v for k, v in counters.items() if v > 0
                    },
                    "placeholders": list(mapping.keys()),
                },
            )

        return SecurityResult(
            decision=Decision.ALLOW,
            module_name=self.name,
            reason="No sensitive data detected.",
        )

    def restore(self, request_id: str, text: str) -> str:
        """Replace placeholder tokens with original values.

        Call this on the LLM response to de-tokenize if needed.
        """
        mapping = self._mappings.get(request_id, {})
        result = text
        for token, original in mapping.items():
            result = result.replace(token, original)
        return result

    def clear_mapping(self, request_id: str) -> None:
        """Remove the mapping for a completed request."""
        self._mappings.pop(request_id, None)
