"""Environment-driven configuration for the observability module."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    db_url: str
    log_level: str
    retention_days: int
    demo_mode: bool
    # DEVELOPMENT_ONLY: disables key-based metadata dropping. Never enable in production.
    development_only_store_content: bool
    async_writes: bool

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            db_url=os.getenv("OBSERVABILITY_DB_URL", "sqlite:///./observability.db"),
            log_level=os.getenv("OBSERVABILITY_LOG_LEVEL", "INFO").upper(),
            retention_days=int(os.getenv("OBSERVABILITY_RETENTION_DAYS", "7")),
            demo_mode=_bool("OBSERVABILITY_DEMO_MODE"),
            development_only_store_content=_bool("OBSERVABILITY_DEVELOPMENT_ONLY_STORE_CONTENT"),
            async_writes=_bool("OBSERVABILITY_ASYNC_WRITES", True),
        )
