import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import DecoyRepository, LogRepository, get_decoy_repo, get_log_repo
from app.main import app
from app.store import store


@pytest.fixture
def repo(tmp_path) -> LogRepository:
    return LogRepository(str(tmp_path / "test.db"))


@pytest.fixture
def decoy_repo(tmp_path) -> DecoyRepository:
    return DecoyRepository(str(tmp_path / "test.db"))


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def no_real_ai(monkeypatch):
    """.env 의 ANTHROPIC_API_KEY 와 무관하게 테스트는 기본적으로 규칙 분석만 쓴다."""
    monkeypatch.setattr(settings, "anthropic_api_key", "")


@pytest.fixture
def client(repo, decoy_repo, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "decoy_store_dir", str(tmp_path / "decoys_store"))
    app.dependency_overrides[get_log_repo] = lambda: repo
    app.dependency_overrides[get_decoy_repo] = lambda: decoy_repo
    store.alerts.clear()
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
