"""Unit tests for the SecurityPipeline."""

import pytest

from app.security.interfaces import Decision, SecurityModule, SecurityResult
from app.proxy.pipeline import SecurityPipeline


# ── Test modules ─────────────────────────────────────────────

class AllowModule(SecurityModule):
    @property
    def name(self) -> str:
        return "test-allow"

    async def inspect(self, content, context):
        return SecurityResult(
            decision=Decision.ALLOW,
            module_name=self.name,
            reason="all good",
        )


class BlockModule(SecurityModule):
    @property
    def name(self) -> str:
        return "test-block"

    async def inspect(self, content, context):
        return SecurityResult(
            decision=Decision.BLOCK,
            module_name=self.name,
            reason="dangerous content",
        )


class ModifyModule(SecurityModule):
    @property
    def name(self) -> str:
        return "test-modify"

    async def inspect(self, content, context):
        return SecurityResult(
            decision=Decision.MODIFY,
            module_name=self.name,
            reason="redacted",
            modified_content=content.replace("secret", "<REDACTED>"),
        )


class ErrorModule(SecurityModule):
    @property
    def name(self) -> str:
        return "test-error"

    async def inspect(self, content, context):
        raise RuntimeError("module crashed")


# ── Tests ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_allow_flow():
    pipeline = SecurityPipeline([AllowModule()])
    result = await pipeline.process("hello", {"request_id": "test"})
    assert result.decision == Decision.ALLOW
    assert result.content == "hello"
    assert len(result.results) == 1


@pytest.mark.asyncio
async def test_block_flow():
    pipeline = SecurityPipeline([BlockModule()])
    result = await pipeline.process("hello", {"request_id": "test"})
    assert result.decision == Decision.BLOCK
    assert result.content is None


@pytest.mark.asyncio
async def test_modify_flow():
    pipeline = SecurityPipeline([ModifyModule()])
    result = await pipeline.process("my secret data", {"request_id": "test"})
    assert result.decision == Decision.ALLOW
    assert result.content == "my <REDACTED> data"


@pytest.mark.asyncio
async def test_multi_module_chaining():
    """MODIFY then ALLOW — content should be modified."""
    pipeline = SecurityPipeline([ModifyModule(), AllowModule()])
    result = await pipeline.process("secret", {"request_id": "test"})
    assert result.decision == Decision.ALLOW
    assert result.content == "<REDACTED>"
    assert len(result.results) == 2


@pytest.mark.asyncio
async def test_block_short_circuits():
    """BLOCK should prevent subsequent modules from running."""
    pipeline = SecurityPipeline([BlockModule(), AllowModule()])
    result = await pipeline.process("hello", {"request_id": "test"})
    assert result.decision == Decision.BLOCK
    assert len(result.results) == 1  # only BlockModule ran


@pytest.mark.asyncio
async def test_error_module_does_not_crash_pipeline():
    """A module exception should be caught and treated as ALLOW."""
    pipeline = SecurityPipeline([ErrorModule(), AllowModule()])
    result = await pipeline.process("hello", {"request_id": "test"})
    assert result.decision == Decision.ALLOW
    assert len(result.results) == 2
    assert result.results[0].metadata.get("error") is True


@pytest.mark.asyncio
async def test_empty_pipeline_allows():
    pipeline = SecurityPipeline([])
    result = await pipeline.process("hello", {"request_id": "test"})
    assert result.decision == Decision.ALLOW
    assert result.content == "hello"


@pytest.mark.asyncio
async def test_pipeline_duration_is_set():
    pipeline = SecurityPipeline([AllowModule()])
    result = await pipeline.process("hello", {"request_id": "test"})
    assert result.duration_ms >= 0
