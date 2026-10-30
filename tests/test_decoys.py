import hashlib
from urllib.parse import quote

import pytest

from app.db import DecoyRepository
from app.services import notifier
from app.store import store

CONTENT = "가짜 인사평가 데이터".encode()
SHA = hashlib.sha256(CONTENT).hexdigest()
NAME = "2026_인사평가_기밀.xlsx"


@pytest.fixture
def slack(monkeypatch):
    sent: list[str] = []

    async def fake_notify(text: str) -> bool:
        sent.append(text)
        return True

    monkeypatch.setattr(notifier, "notify_slack", fake_notify)
    # 라우터들이 import한 이름도 교체
    import app.routers.canary as canary
    import app.routers.logs as logs
    monkeypatch.setattr(canary, "notify_slack", fake_notify)
    monkeypatch.setattr(logs, "notify_slack", fake_notify)
    return sent


def _upload(client, content=CONTENT, name=NAME, based_on_hash=None):
    data = {"based_on_hash": based_on_hash} if based_on_hash else {}
    return client.post("/api/decoys", files={"file": (name, content)}, data=data)


# --- POST /api/decoys (AI 담당 팀원이 디코이 파일 업로드) ---

def test_upload_decoy_registers_file_with_hash(client):
    resp = _upload(client, based_on_hash="orig-hash")

    assert resp.status_code == 200
    body = resp.json()
    assert body["file_name"] == NAME
    assert body["sha256"] == SHA
    assert body["size"] == len(CONTENT)
    assert body["based_on_hash"] == "orig-hash"
    assert body["token_id"]


def test_upload_decoy_rejects_empty_file(client):
    assert _upload(client, content=b"").status_code == 400


def test_uploaded_decoy_listed_for_dashboard(client):
    _upload(client)

    resp = client.get("/api/decoys")

    assert [d["file_name"] for d in resp.json()] == [NAME]


def test_decoys_persist_across_repository_instances(client, decoy_repo):
    _upload(client)

    assert DecoyRepository(decoy_repo.path).find_by_sha256(SHA).file_name == NAME


# --- agent 전용 API ---

def test_agent_endpoints_need_no_auth(client):
    decoy = _upload(client).json()

    assert client.get("/api/agent/decoys").status_code == 200
    assert client.get(f"/api/agent/decoys/{decoy['id']}/file").status_code == 200


def test_agent_lists_only_decoys_with_file(client):
    client.post("/api/decoys/generate", params={"file_name": "no_file.docx"})
    uploaded = _upload(client).json()

    resp = client.get("/api/agent/decoys")

    assert resp.status_code == 200
    assert resp.json() == [{
        "id": uploaded["id"],
        "token_id": uploaded["token_id"],
        "file_name": NAME,
        "sha256": SHA,
        "size": len(CONTENT),
    }]


def test_agent_downloads_decoy_file_without_alert(client, slack):
    decoy = _upload(client).json()

    resp = client.get(f"/api/agent/decoys/{decoy['id']}/file")

    assert resp.status_code == 200
    assert resp.content == CONTENT
    assert resp.headers["content-type"] == "application/octet-stream"
    assert resp.headers["x-decoy-sha256"] == SHA
    assert quote(NAME) in resp.headers["content-disposition"]
    assert slack == []
    assert store.alerts == []


def test_agent_download_unknown_decoy_404(client):
    assert client.get("/api/agent/decoys/nope/file").status_code == 404


# --- 디코이 반출 감지: POST /api/logs 의 file_hash 매칭 ---

def _log(**overrides) -> dict:
    body = {"host": "PC-07", "user": "lee", "event_type": "usb_copy",
            "file_name": NAME, "channel": "usb:E:"}
    body.update(overrides)
    return body


@pytest.mark.parametrize("event_type", ["usb_copy", "email_send", "file_access"])
def test_log_with_decoy_hash_raises_high_alert_and_slack(client, slack, event_type):
    _upload(client)

    resp = client.post("/api/logs", json=_log(event_type=event_type, file_hash=SHA))

    assert resp.status_code == 200
    assert len(store.alerts) == 1
    alert = store.alerts[0]
    assert alert.severity.value == "high"
    assert alert.score == 1.0
    assert alert.reason.startswith("디코이 파일")
    assert alert.host == "PC-07"
    assert alert.related_log_ids == [resp.json()["id"]]
    assert alert.notified is True
    assert len(slack) == 1
    assert NAME in slack[0] and "PC-07" in slack[0] and "lee" in slack[0]


def test_decoy_hash_match_is_case_insensitive(client, slack):
    _upload(client)

    client.post("/api/logs", json=_log(file_hash=SHA.upper()))

    assert len(store.alerts) == 1


def test_log_without_decoy_match_uses_normal_analysis(client, slack):
    _upload(client)

    client.post("/api/logs", json=_log(file_hash="0" * 64, classification="internal"))

    assert store.alerts == []
    assert slack == []


# --- 카나리 비콘: 디코이 레지스트리(DB)에서 토큰 조회 ---

def test_canary_beacon_records_trigger_and_alerts(client, slack, decoy_repo):
    decoy = _upload(client).json()

    resp = client.get(f"/api/canary/{decoy['token_id']}")

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/gif"
    stored = decoy_repo.get(decoy["id"])
    assert stored.triggered is True and stored.trigger_count == 1
    assert len(slack) == 1 and NAME in slack[0]


def test_canary_beacon_unknown_token_is_silent(client, slack):
    resp = client.get("/api/canary/unknown")

    assert resp.status_code == 200
    assert slack == []
