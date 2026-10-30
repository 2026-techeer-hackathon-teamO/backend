import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import DecoyRepository, LogRepository, get_decoy_repo, get_log_repo
from app.main import app
from app.store import store

AGENT_KEY = "test-agent-key"


@pytest.fixture
def repo(tmp_path) -> LogRepository:
    return LogRepository(str(tmp_path / "test.db"))


@pytest.fixture
def decoy_repo(tmp_path) -> DecoyRepository:
    return DecoyRepository(str(tmp_path / "test.db"))


@pytest.fixture
def client(repo, decoy_repo, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "decoy_store_dir", str(tmp_path / "decoys_store"))
    monkeypatch.setattr(settings, "agent_api_key", AGENT_KEY)
    app.dependency_overrides[get_log_repo] = lambda: repo
    app.dependency_overrides[get_decoy_repo] = lambda: decoy_repo
    store.alerts.clear()
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
