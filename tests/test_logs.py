from datetime import datetime, timedelta, timezone

from app.db import LogRepository
from app.models import LogRecord
from app.store import store


def _log(**overrides) -> dict:
    body = {"host": "PC-01", "user": "kim", "event_type": "file_access"}
    body.update(overrides)
    return body


# --- POST /api/logs ---

def test_post_log_returns_record_with_id_and_received_at(client):
    resp = client.post("/api/logs", json=_log(file_name="a.docx", detail={"size": 10}))

    assert resp.status_code == 200
    body = resp.json()
    assert body["id"]
    assert body["received_at"]
    assert body["file_name"] == "a.docx"
    assert body["detail"] == {"size": 10}


def test_post_log_rejects_unknown_event_type(client):
    resp = client.post("/api/logs", json=_log(event_type="print"))

    assert resp.status_code == 422


def test_post_log_rejects_missing_required_field(client):
    resp = client.post("/api/logs", json={"host": "PC-01", "event_type": "file_access"})

    assert resp.status_code == 422


def test_post_log_persists_across_repository_instances(client, repo):
    client.post("/api/logs", json=_log(file_name="a.docx"))

    reopened = LogRepository(repo.path)
    items, total = reopened.list()
    assert total == 1
    assert items[0].file_name == "a.docx"


def test_post_suspicious_log_creates_alert(client):
    client.post(
        "/api/logs",
        json=_log(event_type="usb_copy", classification="confidential", file_name="plan.pdf"),
    )

    assert len(store.alerts) == 1
    assert store.alerts[0].host == "PC-01"


def test_post_log_analysis_uses_recent_logs_from_db(client):
    # 같은 호스트 기밀 접근 5건 누적 + 메일 반출 → 규칙 1 + 규칙 2 = HIGH
    for i in range(4):
        client.post("/api/logs", json=_log(classification="confidential", file_name=f"{i}.docx"))
    client.post(
        "/api/logs",
        json=_log(event_type="email_send", classification="confidential", file_name="x.docx"),
    )

    assert store.alerts[-1].severity.value == "high"


# --- GET /api/logs ---

def test_list_logs_newest_first(client):
    for name in ["1.docx", "2.docx", "3.docx"]:
        client.post("/api/logs", json=_log(file_name=name))

    resp = client.get("/api/logs")

    assert resp.status_code == 200
    assert [r["file_name"] for r in resp.json()] == ["3.docx", "2.docx", "1.docx"]


def test_list_logs_pagination_and_total_header(client):
    for i in range(5):
        client.post("/api/logs", json=_log(file_name=f"{i}.docx"))

    resp = client.get("/api/logs", params={"limit": 2, "offset": 1})

    assert [r["file_name"] for r in resp.json()] == ["3.docx", "2.docx"]
    assert resp.headers["X-Total-Count"] == "5"


def test_list_logs_rejects_invalid_limit(client):
    assert client.get("/api/logs", params={"limit": 0}).status_code == 422
    assert client.get("/api/logs", params={"limit": 1001}).status_code == 422
    assert client.get("/api/logs", params={"offset": -1}).status_code == 422


def test_list_logs_filters(client):
    client.post("/api/logs", json=_log(host="PC-01", user="kim", event_type="usb_copy",
                                       classification="confidential", blocked=True))
    client.post("/api/logs", json=_log(host="PC-02", user="lee", event_type="email_send",
                                       classification="internal"))
    client.post("/api/logs", json=_log(host="PC-01", user="lee", event_type="file_access"))

    def names(**params):
        resp = client.get("/api/logs", params=params)
        return sorted((r["host"], r["user"]) for r in resp.json()), resp.headers["X-Total-Count"]

    assert names(host="PC-01") == ([("PC-01", "kim"), ("PC-01", "lee")], "2")
    assert names(user="lee") == ([("PC-01", "lee"), ("PC-02", "lee")], "2")
    assert names(event_type="email_send") == ([("PC-02", "lee")], "1")
    assert names(classification="confidential") == ([("PC-01", "kim")], "1")
    assert names(blocked="true") == ([("PC-01", "kim")], "1")
    assert names(host="PC-01", user="lee") == ([("PC-01", "lee")], "1")


def test_list_logs_filters_by_period(client, repo):
    base = datetime(2026, 10, 1, tzinfo=timezone.utc)
    for day in range(3):
        repo.add(LogRecord(host="PC-01", user="kim", event_type="file_access",
                           file_name=f"d{day}", received_at=base + timedelta(days=day)))

    resp = client.get("/api/logs", params={
        "since": "2026-10-02T00:00:00Z",
        "until": "2026-10-02T23:59:59Z",
    })

    assert [r["file_name"] for r in resp.json()] == ["d1"]


def test_list_logs_period_treats_naive_datetime_as_utc(client, repo):
    repo.add(LogRecord(host="PC-01", user="kim", event_type="file_access", file_name="d",
                       received_at=datetime(2026, 10, 2, 12, tzinfo=timezone.utc)))

    resp = client.get("/api/logs", params={"since": "2026-10-02T12:00:00"})

    assert [r["file_name"] for r in resp.json()] == ["d"]


# --- GET /api/logs/{id} ---

def test_get_log_by_id(client):
    created = client.post("/api/logs", json=_log(file_name="a.docx")).json()

    resp = client.get(f"/api/logs/{created['id']}")

    assert resp.status_code == 200
    assert resp.json() == created


def test_get_log_not_found(client):
    resp = client.get("/api/logs/nope")

    assert resp.status_code == 404


# --- POST /api/analyze (로그 맥락을 DB에서 읽는지) ---

def test_analyze_uses_recent_logs_from_db(client):
    for i in range(5):
        client.post("/api/logs", json=_log(classification="confidential", file_name=f"{i}.docx"))

    resp = client.post("/api/analyze", json=_log(event_type="usb_copy", classification="confidential"))

    assert resp.json()["severity"] == "high"


def test_total_count_header_exposed_to_browser(client):
    resp = client.get("/api/logs", headers={"Origin": "http://localhost:5173"})

    assert "x-total-count" in resp.headers["access-control-expose-headers"].lower()
