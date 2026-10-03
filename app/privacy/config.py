from pydantic_settings import BaseSettings
from typing import Optional

class PrivacySettings(BaseSettings):
    PRIVACY_MODE: str = "regex_only"
    GEMMA_ENABLED: bool = False
    GEMMA_MODEL_PATH: Optional[str] = None
    GEMMA_DEVICE: str = "auto"
    TOKEN_TTL_SECONDS: int = 300
    TOKEN_ID_LENGTH: int = 8
    PRIVACY_FAIL_CLOSED: bool = True
    ENABLE_PERSON_DETECTION: bool = False

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = PrivacySettings()
