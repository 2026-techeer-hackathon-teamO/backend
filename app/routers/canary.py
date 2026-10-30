"""디코이 파일 생성/등록 + 카나리토큰 비콘 수신."""
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile

from app.db import DecoyRepository, get_decoy_repo
from app.models import CanaryHit, Decoy
from app.services.decoy import build_decoy, save_decoy_file
from app.services.notifier import notify_slack
from app.store import store

router = APIRouter(prefix="/api", tags=["canary"])

# 업로드 상한. 문서형 디코이 기준으로 넉넉히.
_MAX_DECOY_BYTES = 20 * 1024 * 1024


@router.post("/decoys", response_model=Decoy)
async def upload_decoy(
    file: UploadFile = File(..., description="AI가 생성한 디코이 파일"),
    based_on_hash: str | None = Form(None, description="모사한 원본 기밀의 해시"),
    repo: DecoyRepository = Depends(get_decoy_repo),
) -> Decoy:
    """AI 담당이 만든 디코이 파일을 등록. agent가 내려받아 배치하고, 반출 시 해시로 감지한다."""
    content = await file.read(_MAX_DECOY_BYTES + 1)
    if not content:
        raise HTTPException(status_code=400, detail="empty file")
    if len(content) > _MAX_DECOY_BYTES:
        raise HTTPException(status_code=413, detail="file too large")
    decoy = save_decoy_file(content, file.filename or "decoy", based_on_hash)
    return repo.add(decoy)


@router.post("/decoys/generate")
async def generate_decoy(
    file_name: str,
    based_on_hash: str | None = None,
    repo: DecoyRepository = Depends(get_decoy_repo),
) -> dict:
    """유사 기밀 디코이 + 카나리토큰 생성. canary_url을 파일에 심어 배포."""
    decoy, canary_url = build_decoy(file_name, based_on_hash)
    repo.add(decoy)
    return {"decoy": decoy, "canary_url": canary_url}


@router.get("/decoys", response_model=list[Decoy])
async def list_decoys(repo: DecoyRepository = Depends(get_decoy_repo)) -> list[Decoy]:
    return repo.list()


# 1x1 투명 GIF — 문서가 원격 이미지로 비콘을 당기는 전형적 패턴에 사용
_PIXEL = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c000000000100010000020144003b"
)


@router.get("/canary/{token_id}")
async def canary_beacon(
    token_id: str, request: Request, repo: DecoyRepository = Depends(get_decoy_repo)
) -> Response:
    """디코이 파일이 열리면 호출됨 → opener 정보 기록 + 담당자 알림.

    탈취된 파일이 열린 정황이므로 즉시 Slack으로 알립니다.
    """
    decoy = repo.find_by_token(token_id)

    hit = CanaryHit(
        token_id=token_id,
        opener_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    store.add_canary_hit(hit)

    if decoy is not None:
        repo.record_trigger(decoy.id)
        await notify_slack(
            f":fishing_pole_and_fish: 카나리토큰 발동! 디코이 '{decoy.file_name}'이(가) 열렸습니다.\n"
            f"opener_ip={hit.opener_ip}, ua={hit.user_agent}"
        )

    # 눈치채지 못하도록 평범한 1x1 이미지로 응답
    return Response(content=_PIXEL, media_type="image/gif")
