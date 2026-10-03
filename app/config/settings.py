"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Central configuration for the AI Security Proxy."""

    # ── Application ──────────────────────────────────────────
    APP_NAME: str = "ai-security-proxy"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "INFO"

    # ── LLM Provider ─────────────────────────────────────────
    LLM_PROVIDER: str = "mock"  # mock | openai | gemini | ollama
    MOCK_LLM: bool = True

    # OpenAI
    OPENAI_API_KEY: str = ""
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"

    # Google Gemini
    GEMINI_API_KEY: str = ""

    # Ollama
    OLLAMA_BASE_URL: str = "http://localhost:11434"

    # ── Policy Defaults ──────────────────────────────────────
    POLICY_PII_ACTION: str = "redact"       # allow | block | redact
    POLICY_SECRETS_ACTION: str = "redact"    # allow | block | redact
    POLICY_PROMPT_INJECTION_ACTION: str = "block"  # allow | block

    # ── Privacy / De-tokenization ────────────────────────────
    RESTORE_PLACEHOLDERS: bool = False  # Keep placeholders visible in demo by default

    # ── Hardening ────────────────────────────────────────────
    # What to do when a security module crashes or times out.
    #   False = fail open  (request continues; original MVP behaviour)
    #   True  = fail closed (request is blocked; recommended for production)
    SECURITY_FAIL_CLOSED: bool = False
    # Max seconds a single security module may take (0 disables the limit).
    SECURITY_MODULE_TIMEOUT_S: float = 5.0
    # Max seconds to wait for the upstream LLM (0 disables the limit).
    LLM_TIMEOUT_S: float = 60.0

    # ── Plug-in security modules (Person 2 / Person 3) ───────
    # Keep the built-in demo stubs (regex PII + injection) enabled.
    ENABLE_STUB_DETECTORS: bool = True
    # Comma-separated "package.module:ClassName" entries, instantiated with
    # no arguments and inserted before the PolicyEngine. Example:
    #   EXTRA_SECURITY_MODULES=app.pii.presidio_module:PresidioPIIModule
    EXTRA_SECURITY_MODULES: str = ""

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
