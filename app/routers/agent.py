"""agent 전용 API: 배치할 디코이 목록·파일 제공.

agent가 사용자 몰래 다운로드 폴더에 디코이를 넣기 위해 호출합니다.
agent 자신의 다운로드이므로 알림을 보내지 않습니다.
디코이 목록이 새면 미끼가 무력화되므로 X-Agent-Key 로 보호합니다.
"""
import hmac
from urllib.parse import quote

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import FileResponse

from app.config import settings
from app.db import DecoyRepository, get_decoy_repo
from app.models import AgentDecoy
from app.services.decoy import decoy_file_path


def require_agent_key(x_agent_key: str | None = Header(None)) -> None:
    if not settings.agent_api_key:
        raise HTTPException(status_code=503, detail="agent key not configured")
    if not x_agent_key or not hmac.compare_digest(x_agent_key, settings.agent_api_key):
        raise HTTPException(status_code=401, detail="invalid agent key")


router = APIRouter(
    prefix="/api/agent", tags=["agent"], dependencies=[Depends(require_agent_key)]
)


@router.get("/decoys", response_model=list[AgentDecoy])
async def list_agent_decoys(repo: DecoyRepository = Depends(get_decoy_repo)) -> list[AgentDecoy]:
    """파일이 업로드된 디코이만 반환."""
    return [AgentDecoy(**d.model_dump()) for d in repo.list(with_file_only=True)]


@router.get("/decoys/{decoy_id}/file")
async def download_agent_decoy(
    decoy_id: str, repo: DecoyRepository = Depends(get_decoy_repo)
) -> FileResponse:
    decoy = repo.get(decoy_id)
    path = decoy_file_path(decoy_id)
    if decoy is None or decoy.sha256 is None or not path.is_file():
        raise HTTPException(status_code=404, detail="decoy not found")
    return FileResponse(
        path,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(decoy.file_name)}",
            "X-Decoy-SHA256": decoy.sha256,
        },
    )
