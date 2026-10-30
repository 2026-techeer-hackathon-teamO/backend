"""해킹 패턴 판단 AI (Claude).

현재 로그와 같은 PC의 최근 로그 시퀀스를 Claude에게 보내 내부자 유출·해킹 의심 여부를 판정합니다.
ANTHROPIC_API_KEY 가 없거나 호출이 실패·거절되면 None을 돌려주고, 호출부는 규칙 분석으로 폴백합니다.
"""
import anthropic
from pydantic import BaseModel, Field, ValidationError

from app.config import settings
from app.models import LogRecord, Severity

_SYSTEM = """당신은 기업 DLP(정보 유출 방지) 시스템의 보안 분석가입니다.
회사가 관리하는 업무용 PC의 agent가 보낸 이벤트 로그를 보고, 내부자에 의한 기밀 유출이나
계정 탈취·해킹으로 의심되는 패턴인지 판단합니다. 방어 목적의 분석이며 판단 결과는 보안 담당자에게 전달됩니다.

이벤트 종류: file_access(기밀 파일 열람/다운로드), email_send(메일 첨부 전송 시도),
usb_copy(이동식 저장소 복사 시도), blocked(정책에 의해 차단된 시도).

의심 신호의 예:
- 짧은 시간에 많은 기밀 파일 접근 후 메일/USB 반출 (대량 반출)
- 새벽·주말 등 업무 외 시간대 활동 (received_at은 UTC, 한국 시간은 +9시간)
- 차단된 뒤 다른 채널로 반복 시도 (우회 시도)
- 평소와 다른 사용자 계정이 같은 PC에서 활동
- 개인 메일·외부 저장소 등 외부 채널로 기밀 전송

정상 업무로 설명되는 활동(단발성 열람, internal 등급의 사내 공유 등)은 의심하지 마세요.
오탐은 담당자의 피로를 키우므로 근거가 분명할 때만 suspicious=true로 판정합니다.
score는 0.0~1.0 의심도, reason은 담당자가 바로 이해할 한국어 한두 문장, patterns는 해당하는 의심 패턴 이름 목록입니다."""


class AiVerdict(BaseModel):
    suspicious: bool
    severity: Severity
    score: float = Field(ge=0.0, le=1.0)
    reason: str
    patterns: list[str]


_VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "suspicious": {"type": "boolean"},
        "severity": {"type": "string", "enum": [s.value for s in Severity]},
        "score": {"type": "number"},
        "reason": {"type": "string"},
        "patterns": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["suspicious", "severity", "score", "reason", "patterns"],
    "additionalProperties": False,
}

_FIELDS = {"received_at", "host", "user", "event_type", "file_name", "classification",
           "channel", "blocked", "detail"}

_client: anthropic.AsyncAnthropic | None = None


def ai_enabled() -> bool:
    return bool(settings.anthropic_api_key)


def _get_client() -> anthropic.AsyncAnthropic:
    global _client
    if _client is None:
        _client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key, timeout=60.0)
    return _client


def _event(log: LogRecord) -> str:
    return log.model_dump_json(include=_FIELDS)


def _prompt(log: LogRecord, history: list[LogRecord]) -> str:
    past = "\n".join(_event(h) for h in history) or "(없음)"
    return (
        f"## 같은 PC({log.host})의 최근 이벤트 (오래된 순)\n{past}\n\n"
        f"## 판단할 현재 이벤트\n{_event(log)}\n\n"
        "현재 이벤트를 최근 맥락과 함께 보고 유출·해킹 의심 여부를 판정하세요."
    )


async def judge(log: LogRecord, history: list[LogRecord]) -> AiVerdict | None:
    """의심 판정. None이면 판단 불가(키 없음/API 오류/거절/형식 오류) → 규칙으로 폴백."""
    if not ai_enabled():
        return None
    try:
        response = await _get_client().beta.messages.create(
            model=settings.ai_model,
            max_tokens=16000,
            system=_SYSTEM,
            messages=[{"role": "user", "content": _prompt(log, history)}],
            output_config={
                "effort": "medium",
                "format": {"type": "json_schema", "schema": _VERDICT_SCHEMA},
            },
            # 보안 분석이라 분류기에 거절될 수 있음 → 서버가 권장 모델로 재시도
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
    except anthropic.RateLimitError:
        print("[ai_analyzer] rate limited → 규칙 분석으로 폴백")
        return None
    except anthropic.APIStatusError as exc:
        print(f"[ai_analyzer] API 오류 {exc.status_code} → 규칙 분석으로 폴백")
        return None
    except anthropic.APIConnectionError as exc:
        print(f"[ai_analyzer] 연결 실패 {exc} → 규칙 분석으로 폴백")
        return None

    if response.stop_reason != "end_turn":
        print(f"[ai_analyzer] 판정 불가 stop_reason={response.stop_reason} → 규칙 분석으로 폴백")
        return None
    text = next((b.text for b in response.content if b.type == "text"), None)
    try:
        return AiVerdict.model_validate_json(text or "")
    except ValidationError:
        print("[ai_analyzer] 응답 형식 오류 → 규칙 분석으로 폴백")
        return None
