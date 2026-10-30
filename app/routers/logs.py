"""agent가 보낸 DLP 로그 수집 + 디코이 반출 감지 + 즉시 AI 분석."""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.db import DecoyRepository, LogRepository, get_decoy_repo, get_log_repo
from app.models import Alert, Decoy, EventType, LogIn, LogRecord, Severity
from app.services.analyzer import analyze
from app.services.notifier import notify_slack
from app.store import store

router = APIRouter(prefix="/api/logs", tags=["logs"])


def _decoy_alert(record: LogRecord, decoy: Decoy) -> Alert:
    """정상 업무에서 건드릴 일이 없는 미끼이므로 등급과 무관하게 최고 위험으로 본다."""
    return Alert(
        severity=Severity.HIGH,
        reason=(
            f"디코이 파일 '{decoy.file_name}' {record.event_type.value} 감지"
            f" (user={record.user}, channel={record.channel})"
        ),
        score=1.0,
        related_log_ids=[record.id],
        host=record.host,
    )


@router.post("", response_model=LogRecord)
async def ingest_log(
    payload: LogIn,
    repo: LogRepository = Depends(get_log_repo),
    decoys: DecoyRepository = Depends(get_decoy_repo),
) -> LogRecord:
    record = repo.add(LogRecord(**payload.model_dump()))

    # agent가 몰래 배치한 디코이를 건드렸으면 규칙 분석 없이 바로 알림
    decoy = decoys.find_by_sha256(record.file_hash) if record.file_hash else None
    if decoy is not None:
        alert = store.add_alert(_decoy_alert(record, decoy))
        alert.notified = await notify_slack(
            f":rotating_light: 디코이 반출/접근 감지 ({record.event_type.value})\n"
            f"파일: {decoy.file_name}\nhost={record.host}, user={record.user},"
            f" channel={record.channel}"
        )
        return record

    # 최근 로그 맥락과 함께 분석 → 의심되면 알림 적재 + Slack
    recent = repo.recent(50)
    alert = analyze(record, recent)
    if alert is not None:
        store.add_alert(alert)
        ok = await notify_slack(
            f":rotating_light: 유출 의심 ({alert.severity.value}, score={alert.score})\n"
            f"host={alert.host}\n근거: {alert.reason}"
        )
        alert.notified = ok

    return record


@router.get("", response_model=list[LogRecord])
async def list_logs(
    response: Response,
    host: str | None = None,
    user: str | None = None,
    event_type: EventType | None = None,
    classification: str | None = None,
    blocked: bool | None = None,
    since: datetime | None = Query(None, description="이 시각 이후 수신 (시간대 없으면 UTC)"),
    until: datetime | None = Query(None, description="이 시각 이전 수신 (시간대 없으면 UTC)"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    repo: LogRepository = Depends(get_log_repo),
) -> list[LogRecord]:
    """최신순 목록. 필터에 걸린 전체 건수는 X-Total-Count 헤더로 반환."""
    items, total = repo.list(
        host=host, user=user, event_type=event_type, classification=classification,
        blocked=blocked, since=since, until=until, limit=limit, offset=offset,
    )
    response.headers["X-Total-Count"] = str(total)
    return items


@router.get("/{log_id}", response_model=LogRecord)
async def get_log(log_id: str, repo: LogRepository = Depends(get_log_repo)) -> LogRecord:
    record = repo.get(log_id)
    if record is None:
        raise HTTPException(status_code=404, detail="log not found")
    return record
