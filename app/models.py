from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _id() -> str:
    return uuid4().hex


class EventType(str, Enum):
    """agent가 보고하는 DLP 이벤트 종류."""
    FILE_ACCESS = "file_access"       # 기밀 파일 열람/다운로드
    EMAIL_SEND = "email_send"         # 메일 첨부 전송 시도
    USB_COPY = "usb_copy"             # 이동식 저장소 복사 시도
    BLOCKED = "blocked"               # 정책에 의해 차단됨


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class LogIn(BaseModel):
    """agent → backend 로 전송되는 로그."""
    host: str                         # PC 식별자 (hostname/asset id)
    user: str                         # 로그인 사용자
    event_type: EventType
    file_name: str | None = None
    file_hash: str | None = None      # 기밀 파일 식별용 해시
    classification: str | None = None  # 예: "confidential", "internal"
    channel: str | None = None        # 예: "gmail", "usb:E:"
    blocked: bool = False
    detail: dict = Field(default_factory=dict)


class LogRecord(LogIn):
    id: str = Field(default_factory=_id)
    received_at: datetime = Field(default_factory=_now)


class Alert(BaseModel):
    id: str = Field(default_factory=_id)
    created_at: datetime = Field(default_factory=_now)
    severity: Severity
    reason: str                       # AI/규칙이 의심한 근거
    score: float = 0.0                # 0.0 ~ 1.0 의심도
    related_log_ids: list[str] = Field(default_factory=list)
    host: str | None = None
    notified: bool = False            # Slack 전송 여부


class Decoy(BaseModel):
    id: str = Field(default_factory=_id)
    created_at: datetime = Field(default_factory=_now)
    token_id: str = Field(default_factory=_id)   # 카나리토큰 식별자
    file_name: str                    # 디코이 파일명 (유출 기밀과 유사)
    based_on_hash: str | None = None  # 어떤 기밀을 모사했는지
    deployed_host: str | None = None
    triggered: bool = False           # 열려서 비콘이 울렸는지
    trigger_count: int = 0
    sha256: str | None = None         # 업로드된 디코이 파일 해시 (agent 로그 file_hash와 매칭)
    size: int | None = None           # 업로드된 디코이 파일 크기(bytes)


class AgentDecoy(BaseModel):
    """agent가 배치할 디코이 목록 항목 (GET /api/agent/decoys)."""
    id: str
    token_id: str
    file_name: str
    sha256: str
    size: int


class CanaryHit(BaseModel):
    id: str = Field(default_factory=_id)
    at: datetime = Field(default_factory=_now)
    token_id: str
    opener_ip: str | None = None
    user_agent: str | None = None
    extra: dict = Field(default_factory=dict)
