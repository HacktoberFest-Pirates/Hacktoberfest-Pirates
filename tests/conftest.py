"""Shared fixtures for the test suite."""

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def app():
    """Create a fresh application instance for each test."""
    return create_app()


@pytest.fixture
def client(app):
    """Synchronous test client wrapping the FastAPI app."""
    return TestClient(app)
