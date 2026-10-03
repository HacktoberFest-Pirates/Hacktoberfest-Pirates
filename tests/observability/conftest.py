import pytest

from app.observability.config import Settings
from app.observability.repository import ObservabilityRepository
from app.observability.service import ObservabilityService, set_service


@pytest.fixture()
def svc():
    settings = Settings(db_url="sqlite://", log_level="CRITICAL", retention_days=7, demo_mode=False,
                        development_only_store_content=False, async_writes=False)
    s = ObservabilityService(settings, ObservabilityRepository("sqlite://"), strict=True)
    set_service(s)
    yield s
    set_service(None)
