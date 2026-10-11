import sys
from pathlib import Path

# Add project root directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uuid
import pytest
from fastapi.testclient import TestClient
from database import engine, Base, SessionLocal
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """
    Ensure database tables exist before test suite executes.
    Crucial for CI/CD environments with freshly initialized databases.
    """
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    """Provides a fresh FastAPI test client."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db():
    """Provides a database session for tests needing direct verification."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def unique_string(prefix: str = "test") -> str:
    """Generates a random unique string to ensure tests are isolated and idempotent."""
    return f"{prefix}_{uuid.uuid4().hex[:8]}"
