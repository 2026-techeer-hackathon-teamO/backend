"""agent가 보낸 DLP 로그 수집 + 즉시 AI 분석."""
from fastapi import APIRouter

from app.models import LogIn, LogRecord
from app.services.analyzer import analyze
from app.services.notifier import notify_slack
from app.store import store

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.post("", response_model=LogRecord)
async def ingest_log(payload: LogIn) -> LogRecord:
    record = store.add_log(LogRecord(**payload.model_dump()))

    # 최근 로그 맥락과 함께 분석 → 의심되면 알림 적재 + Slack
    recent = store.logs[-50:]
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
async def list_logs(limit: int = 100) -> list[LogRecord]:
    return store.logs[-limit:][::-1]
