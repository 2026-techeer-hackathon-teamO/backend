"""로그를 분석해 해킹/유출 의심 패턴을 판단.

로컬 규칙 기반 점수만 사용합니다. 외부 모델 API를 호출하지 않습니다.
"""
from app.models import Alert, EventType, LogRecord, Severity


def analyze(log: LogRecord, recent: list[LogRecord]) -> Alert | None:
    """단일 로그 + 최근 로그 맥락으로 의심 여부 판정. 의심 없으면 None."""
    score = 0.0
    reasons: list[str] = []

    # 규칙 1: 기밀이 외부 채널(메일/USB)로 나감
    if log.event_type in (EventType.EMAIL_SEND, EventType.USB_COPY):
        if (log.classification or "").lower() == "confidential":
            score += 0.6
            reasons.append(f"기밀 파일의 {log.event_type.value} 시도")

    # 규칙 2: 같은 호스트에서 단시간 다수 기밀 접근 (대량 반출 징후)
    same_host_confidential = [
        r for r in recent
        if r.host == log.host and (r.classification or "").lower() == "confidential"
    ]
    if len(same_host_confidential) >= 5:
        score += 0.3
        reasons.append(f"{log.host}에서 기밀 파일 다수 접근({len(same_host_confidential)}건)")

    # 규칙 3: 차단된 이벤트는 그 자체로 주의 신호
    if log.blocked:
        score += 0.2
        reasons.append("정책에 의해 차단된 시도")


    if score < 0.5:
        return None

    severity = Severity.HIGH if score >= 0.8 else Severity.MEDIUM
    return Alert(
        severity=severity,
        reason="; ".join(reasons),
        score=round(min(score, 1.0), 2),
        related_log_ids=[log.id],
        host=log.host,
    )
