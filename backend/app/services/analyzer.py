"""로그를 분석해 해킹/유출 의심 패턴을 판단.

[Zero-Access 기밀 보안 정책]
기밀 파일(confidential)은 애초에 열람·복사·이동·전송 등 모든 접근이 불가한 자산으로 가정합니다.
따라서 기밀 파일에 대한 임의의 접근이 포착되면 단 1건이라도 즉시 100% 이상 탐지(HIGH 위험도)로 판정합니다.
그 외 일반/내부 파일은 반출성 이벤트 및 AI 맥락 분석을 거쳐 판정합니다.
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

    is_confidential = (log.classification or "").lower() == "confidential"

    # [핵심] Zero-Access 원칙: 모든 접근이 불가한 기밀 파일에 대한 어떠한 접근이든 즉시 이상 탐지
    if is_confidential:
        score = 1.0
        target = log.file_name or "기밀 파일"
        reasons.append(f"접근 불가 기밀 파일({target})에 대한 {log.event_type.value} 무단 접근 포착 (Zero-Access 정책 위반)")
        return score, reasons

    # 규칙 1: 일반/내부 파일의 외부 채널(메일/USB) 반출 시도
    if log.event_type in (EventType.EMAIL_SEND, EventType.USB_COPY):
        score += 0.5
        reasons.append(f"외부 채널로의 파일 {log.event_type.value} 시도")

    # 규칙 2: 같은 호스트에서 단시간 다수 활동
    same_host_events = [r for r in recent if r.host == log.host]
    if len(same_host_events) >= 10:
        score += 0.3
        reasons.append(f"{log.host}에서 단시간 다수 이벤트({len(same_host_events)}건)")

    # 규칙 3: 차단된 이벤트는 그 자체로 주의 신호
    if log.blocked:
        score += 0.3
        reasons.append("보안 정책에 의해 차단된 시도")

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

    # 기밀 파일의 Zero-Access 위반은 규칙 단계에서 즉시 판정 완료
    if score >= 1.0:
        return _rule_alert(log, score, reasons)

    # 그 외 이벤트에 대해 AI 분석 수행
    if ai_analyzer.ai_enabled() and (score > 0 or log.event_type in _EXFIL_EVENTS):
        history = [r for r in recent if r.host == log.host and r.id != log.id][-_AI_HISTORY:]
        verdict = await ai_analyzer.judge(log, history)
        if verdict is not None:
            return _ai_alert(log, verdict)

    return _rule_alert(log, score, reasons)
