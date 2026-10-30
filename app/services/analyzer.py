"""로그를 분석해 해킹/유출 의심 패턴을 판단.

1) 규칙 기반 스코어링을 먼저 돌리고,
2) 반출성 이벤트이거나 규칙에 신호가 잡히면 해킹 패턴 AI(Claude)가 같은 PC의 최근 로그 맥락으로 최종 판정.
   AI를 쓸 수 없으면(키 없음/오류/거절) 규칙 결과로 판정합니다.
"""
from app.models import Alert, EventType, LogRecord, Severity
from app.services import ai_analyzer

# 이 이벤트들은 규칙 신호가 없어도 AI가 맥락을 본다
_EXFIL_EVENTS = (EventType.EMAIL_SEND, EventType.USB_COPY, EventType.BLOCKED)

# AI 판정이 suspicious여도 이 의심도 미만이면 알리지 않는다 (오탐 억제)
_AI_ALERT_THRESHOLD = 0.5

_AI_HISTORY = 30


def _rule_score(log: LogRecord, recent: list[LogRecord]) -> tuple[float, list[str]]:
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

    return score, reasons


def _rule_alert(log: LogRecord, score: float, reasons: list[str]) -> Alert | None:
    if score < 0.5:
        return None
    return Alert(
        severity=Severity.HIGH if score >= 0.8 else Severity.MEDIUM,
        reason="; ".join(reasons),
        score=round(min(score, 1.0), 2),
        related_log_ids=[log.id],
        host=log.host,
        analyzed_by="rule",
    )


def _ai_alert(log: LogRecord, verdict: ai_analyzer.AiVerdict) -> Alert | None:
    if not verdict.suspicious or verdict.score < _AI_ALERT_THRESHOLD:
        return None
    patterns = f" [{', '.join(verdict.patterns)}]" if verdict.patterns else ""
    return Alert(
        severity=verdict.severity,
        reason=f"{verdict.reason}{patterns}",
        score=round(verdict.score, 2),
        related_log_ids=[log.id],
        host=log.host,
        analyzed_by="ai",
    )


async def analyze(log: LogRecord, recent: list[LogRecord]) -> Alert | None:
    """단일 로그 + 최근 로그 맥락으로 의심 여부 판정. 의심 없으면 None."""
    score, reasons = _rule_score(log, recent)

    if ai_analyzer.ai_enabled() and (score > 0 or log.event_type in _EXFIL_EVENTS):
        history = [r for r in recent if r.host == log.host and r.id != log.id][-_AI_HISTORY:]
        verdict = await ai_analyzer.judge(log, history)
        if verdict is not None:
            return _ai_alert(log, verdict)

    return _rule_alert(log, score, reasons)
