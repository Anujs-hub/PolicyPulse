"""Shared fixtures. Every test gets its own temporary SQLite file: real data is never touched."""
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

GOOD = {"user_id": "bob", "role": "analyst", "resource_id": "siem-dashboard", "action": "read",
        "device_trust": "trusted", "mfa_verified": True, "failed_logins": 0, "access_context": "normal"}


@pytest.fixture
def settings(tmp_path):
    return Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}", _env_file=None)


@pytest.fixture
def client(settings):
    app = create_app(settings)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def db(client):
    session = client.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def good():
    return dict(GOOD)


def evaluate(client, **overrides):
    payload = dict(GOOD, **overrides)
    r = client.post("/api/evaluate", json=payload)
    assert r.status_code == 200, r.text
    return r.json()
