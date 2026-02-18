"""Pytest configuration and fixtures."""
import pytest


@pytest.fixture(scope="session")
def api_client():
    """Create test client for API."""
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)
