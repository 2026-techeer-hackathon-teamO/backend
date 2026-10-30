"""보안 담당자용 의심 이벤트 조회 + 수동 분석 트리거."""
from fastapi import APIRouter, Depends

from app.db import LogRepository, get_log_repo
from app.models import Alert, LogIn, LogRecord
from app.services.analyzer import analyze
from app.store import store

router = APIRouter(prefix="/api", tags=["alerts"])


@router.get("/alerts", response_model=list[Alert])
async def list_alerts() -> list[Alert]:
    return store.alerts[::-1]


@router.post("/analyze", response_model=Alert | None)
async def analyze_once(payload: LogIn, repo: LogRepository = Depends(get_log_repo)) -> Alert | None:
    """임의 로그 하나를 분석만 해보는 디버그/시연용 엔드포인트 (저장 안 함)."""
    record = LogRecord(**payload.model_dump())
    return analyze(record, repo.recent(50))
