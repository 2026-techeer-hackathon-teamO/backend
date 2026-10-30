"""agent가 보낸 DLP 로그 수집 + 디코이 반출 감지 + 해킹 패턴 AI 분석(백그라운드)."""
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response

from app.db import DecoyRepository, LogRepository, get_decoy_repo, get_log_repo
from app.models import Alert, Decoy, EventType, LogIn, LogRecord, Severity
from app.services.analyzer import analyze
from app.services.decoy import synthesize_transparent_decoy
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
        analyzed_by="decoy",
    )


async def _analyze_and_alert(record: LogRecord, repo: LogRepository) -> None:
    """최근 로그 맥락과 함께 분석 → 의심되면 알림 적재 + Slack.

    AI 판단은 수 초가 걸리므로 응답 후 백그라운드에서 실행한다.
    """
    alert = await analyze(record, repo.recent(50))
    if alert is None:
        return
    store.add_alert(alert)
    judge = "Zero-Access 규칙 판정" if alert.analyzed_by == "rule" else "해킹 패턴 AI 판단"
    alert.notified = await notify_slack(
        f":rotating_light: 유출 의심 ({alert.severity.value}, score={alert.score}) · {judge}\n"
        f"host={alert.host}, user={record.user}\n근거: {alert.reason}"
    )


def _synthesize_decoy_replacement(file_name: str, file_hash: str | None, decoys: DecoyRepository) -> None:
    """기밀 파일 접근 시 공격자가 접근했다고 느끼도록 동일 맥락의 투명 대체 디코이를 자동 합성."""
    try:
        decoy, _ = synthesize_transparent_decoy(file_name, based_on_hash=file_hash)
        decoys.add(decoy)
    except Exception:
        pass


@router.post("", response_model=LogRecord)
async def ingest_log(
    payload: LogIn,
    background: BackgroundTasks,
    repo: LogRepository = Depends(get_log_repo),
    decoys: DecoyRepository = Depends(get_decoy_repo),
) -> LogRecord:
    record = repo.add(LogRecord(**payload.model_dump()))

    # 1. agent가 몰래 배치한 디코이를 건드렸으면 규칙 분석 없이 즉시 최고 위험 알림
    decoy = decoys.find_by_sha256(record.file_hash) if record.file_hash else None
    if decoy is not None:
        alert = store.add_alert(_decoy_alert(record, decoy))
        alert.notified = await notify_slack(
            f":rotating_light: 디코이 반출/접근 감지 ({record.event_type.value})\n"
            f"파일: {decoy.file_name}\nhost={record.host}, user={record.user},"
            f" channel={record.channel}"
        )
        return record

    # 2. 기밀 파일 접근 시: 공격자 유인용 투명 대체 디코이 자동 합성 백그라운드 등록
    is_confidential = (record.classification or "").lower() == "confidential"
    if is_confidential and record.file_name:
        background.add_task(_synthesize_decoy_replacement, record.file_name, record.file_hash, decoys)

    # 3. 이상 탐지 및 Slack 알림 트리거
    background.add_task(_analyze_and_alert, record, repo)
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
