import json
from types import SimpleNamespace

import anthropic
import httpx2
import pytest

from app.config import settings
from app.models import LogRecord, Severity
from app.services import ai_analyzer
from app.services.ai_analyzer import AiVerdict
from app.store import store


def _log(**overrides) -> dict:
    body = {"host": "PC-01", "user": "kim", "event_type": "file_access"}
    body.update(overrides)
    return body


@pytest.fixture
def slack(monkeypatch):
    sent: list[str] = []

    async def fake_notify(text: str) -> bool:
        sent.append(text)
        return True

    import app.routers.logs as logs
    monkeypatch.setattr(logs, "notify_slack", fake_notify)
    return sent


@pytest.fixture
def ai(monkeypatch):
    """AI 판단을 가짜로 교체. calls에 (log, history)가 쌓이고 verdict를 바꿔 끼울 수 있다."""
    state = SimpleNamespace(calls=[], verdict=None)

    async def fake_judge(log, history):
        state.calls.append((log, history))
        return state.verdict

    monkeypatch.setattr(settings, "anthropic_api_key", "test-key")
    monkeypatch.setattr(ai_analyzer, "judge", fake_judge)
    return state


SUSPICIOUS = AiVerdict(
    suspicious=True, severity=Severity.HIGH, score=0.92,
    reason="퇴근 시간대 기밀 파일 USB 대량 반출", patterns=["대량 반출", "비정상 시간대"],
)
BENIGN = AiVerdict(
    suspicious=False, severity=Severity.LOW, score=0.1, reason="정상 업무 패턴", patterns=[],
)


# --- 수집 파이프라인에서의 AI 판단 ---

def test_ai_suspicious_verdict_creates_ai_alert_and_slack(client, slack, ai):
    ai.verdict = SUSPICIOUS

    resp = client.post("/api/logs", json=_log(event_type="usb_copy", classification="confidential"))

    assert resp.status_code == 200
    assert len(store.alerts) == 1
    alert = store.alerts[0]
    assert alert.analyzed_by == "ai"
    assert alert.severity == Severity.HIGH
    assert alert.score == 0.92
    assert "USB 대량 반출" in alert.reason
    assert alert.related_log_ids == [resp.json()["id"]]
    assert alert.notified is True
    assert len(slack) == 1 and "AI" in slack[0]


def test_ai_benign_verdict_overrides_rule_alert(client, slack, ai):
    ai.verdict = BENIGN

    # 규칙만으로는 알림이 나는 로그(기밀 USB 반출)
    client.post("/api/logs", json=_log(event_type="usb_copy", classification="confidential"))

    assert store.alerts == []
    assert slack == []


def test_ai_low_score_suspicious_is_not_alerted(client, slack, ai):
    ai.verdict = SUSPICIOUS.model_copy(update={"score": 0.3})

    client.post("/api/logs", json=_log(event_type="email_send"))

    assert store.alerts == []


def test_ai_failure_falls_back_to_rules(client, slack, ai):
    ai.verdict = None

    client.post("/api/logs", json=_log(event_type="usb_copy", classification="confidential"))

    assert len(store.alerts) == 1
    assert store.alerts[0].analyzed_by == "rule"


@pytest.mark.parametrize("event_type", ["usb_copy", "email_send", "blocked"])
def test_exfil_events_always_go_to_ai(client, ai, event_type):
    ai.verdict = BENIGN

    client.post("/api/logs", json=_log(event_type=event_type))

    assert len(ai.calls) == 1


def test_plain_file_access_without_rule_signal_skips_ai(client, ai):
    client.post("/api/logs", json=_log(event_type="file_access", classification="internal"))

    assert ai.calls == []


def test_ai_gets_same_host_history_without_current_log(client, ai):
    ai.verdict = BENIGN
    client.post("/api/logs", json=_log(host="PC-01", file_name="a.docx"))
    client.post("/api/logs", json=_log(host="PC-02", file_name="other.docx"))

    created = client.post("/api/logs", json=_log(host="PC-01", event_type="usb_copy",
                                                 file_name="b.docx")).json()

    log, history = ai.calls[-1]
    assert log.id == created["id"]
    assert [h.file_name for h in history] == ["a.docx"]


def test_ai_disabled_uses_rules_only(client, slack, monkeypatch):
    called = []

    async def fake_judge(log, history):
        called.append(log)

    monkeypatch.setattr(ai_analyzer, "judge", fake_judge)

    client.post("/api/logs", json=_log(event_type="usb_copy", classification="confidential"))

    assert called == []
    assert store.alerts[0].analyzed_by == "rule"


def test_decoy_alert_marked_as_decoy(client, slack, ai):
    client.post("/api/decoys", files={"file": ("bait.xlsx", b"bait")})
    import hashlib

    client.post("/api/logs", json=_log(event_type="usb_copy",
                                       file_hash=hashlib.sha256(b"bait").hexdigest()))

    assert store.alerts[0].analyzed_by == "decoy"
    assert ai.calls == []


def test_analyze_endpoint_uses_ai(client, ai):
    ai.verdict = SUSPICIOUS

    resp = client.post("/api/analyze", json=_log(event_type="usb_copy"))

    assert resp.json()["analyzed_by"] == "ai"
    assert store.alerts == []  # 분석만, 저장 안 함


# --- judge(): Claude API 호출과 응답 처리 ---

class FakeMessages:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.kwargs = response, error, None

    async def create(self, **kwargs):
        self.kwargs = kwargs
        if self.error:
            raise self.error
        return self.response


def _fake_client(monkeypatch, **kw) -> FakeMessages:
    messages = FakeMessages(**kw)
    client = SimpleNamespace(beta=SimpleNamespace(messages=messages))
    monkeypatch.setattr(ai_analyzer, "_get_client", lambda: client)
    monkeypatch.setattr(settings, "anthropic_api_key", "test-key")
    return messages


def _response(text: str, stop_reason: str = "end_turn"):
    return SimpleNamespace(
        stop_reason=stop_reason,
        content=[SimpleNamespace(type="thinking", thinking=""),
                 SimpleNamespace(type="text", text=text)],
    )


def _record(**overrides) -> LogRecord:
    return LogRecord(**_log(**overrides))


@pytest.mark.anyio
async def test_judge_parses_structured_verdict(monkeypatch):
    messages = _fake_client(monkeypatch, response=_response(SUSPICIOUS.model_dump_json()))
    history = [_record(file_name="a.docx")]

    verdict = await ai_analyzer.judge(_record(event_type="usb_copy", file_name="b.docx"), history)

    assert verdict == SUSPICIOUS
    kw = messages.kwargs
    assert kw["model"] == settings.ai_model
    assert kw["fallbacks"] == "default"
    assert kw["betas"] == ["server-side-fallback-2026-07-01"]
    assert kw["output_config"]["format"]["type"] == "json_schema"
    assert kw["output_config"]["effort"] == "medium"
    prompt = json.dumps(kw["messages"], ensure_ascii=False)
    assert "b.docx" in prompt and "a.docx" in prompt


@pytest.mark.anyio
async def test_judge_returns_none_on_refusal(monkeypatch):
    _fake_client(monkeypatch, response=_response("", stop_reason="refusal"))

    assert await ai_analyzer.judge(_record(), []) is None


@pytest.mark.anyio
async def test_judge_returns_none_on_invalid_json(monkeypatch):
    _fake_client(monkeypatch, response=_response("not json"))

    assert await ai_analyzer.judge(_record(), []) is None


@pytest.mark.anyio
async def test_judge_returns_none_on_api_error(monkeypatch):
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    _fake_client(monkeypatch, error=anthropic.APIConnectionError(request=request))

    assert await ai_analyzer.judge(_record(), []) is None


@pytest.mark.anyio
async def test_judge_disabled_without_key(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "")

    assert await ai_analyzer.judge(_record(), []) is None
