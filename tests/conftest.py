import pytest
from fastapi.testclient import TestClient

from app.db import LogRepository, get_log_repo
from app.main import app
from app.store import store


@pytest.fixture
def repo(tmp_path) -> LogRepository:
    return LogRepository(str(tmp_path / "test.db"))


@pytest.fixture
def client(repo):
    app.dependency_overrides[get_log_repo] = lambda: repo
    store.alerts.clear()
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
