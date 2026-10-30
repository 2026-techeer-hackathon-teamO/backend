"""디코이(허니팟) 파일 + 카나리토큰 생성.

지금까지 유출/다운로드된 기밀과 "그럴듯하게 유사한" 미끼 파일을 만들고,
파일을 열면 서버의 카나리 엔드포인트로 비콘이 울리도록 토큰을 심습니다.
그 파일이 열리면(= 탈취·반출된 정황) 담당자에게 즉시 알림이 갑니다.

카나리토큰은 Thinkst Canarytokens 같은 방어 기법과 동일한 개념입니다.

현재는 스캐폴드: 디코이 레코드와 카나리 URL을 생성하는 지점까지만 구현.
TODO:
  - 유출 기밀의 메타데이터를 바탕으로 유사 파일명/내용 생성
  - 문서 포맷별 비콘 임베드 (예: docx 내부의 원격 리소스 참조 → 열람 시 CANARY_BASE_URL 호출)

디코이 파일 자체는 AI 담당 팀원이 만들어 POST /api/decoys 로 업로드하고,
agent가 GET /api/agent/decoys/{id}/file 로 받아 사용자 다운로드 폴더에 배치합니다.
"""
import hashlib
from pathlib import Path

from app.config import settings
from app.models import Decoy


def build_decoy(file_name: str, based_on_hash: str | None = None) -> tuple[Decoy, str]:
    """디코이 레코드와, 파일에 심을 카나리 비콘 URL을 반환."""
    decoy = Decoy(file_name=file_name, based_on_hash=based_on_hash)
    canary_url = f"{settings.canary_base_url.rstrip('/')}/api/canary/{decoy.token_id}"
    return decoy, canary_url


def decoy_file_path(decoy_id: str) -> Path:
    """업로드된 디코이 파일 저장 위치. 파일명 대신 id를 써서 경로 조작을 막는다."""
    return Path(settings.decoy_store_dir) / decoy_id


def save_decoy_file(content: bytes, file_name: str, based_on_hash: str | None = None) -> Decoy:
    """업로드된 디코이 파일을 저장하고, 반출 매칭용 SHA-256을 담은 레코드를 반환."""
    decoy = Decoy(
        file_name=Path(file_name).name,
        based_on_hash=based_on_hash,
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
    )
    path = decoy_file_path(decoy.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return decoy
