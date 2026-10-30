"""승인된 문서 사본에 확인 링크를 추가합니다. 파일 열람만으로 HTTP 요청을 보장하지 않습니다."""
from app.config import settings
from app.models import Decoy
from backend.documents import traced_copy, beacon_document, validate_document, remote_image_docx
import re


def safe_filename(name):
    # 헤더 삽입·경로 조작을 막고 저장 경로와 사용자에게 표시할 파일명을 분리합니다.
    name = name.replace('\\', '/').rsplit('/', 1)[-1]
    name = re.sub(r'[\x00-\x1f\x7f<>:"|?*]', '_', name).strip(' .')[:180]
    return name or 'approved-document.txt'


def render_decoy(content, name, url, file_id, mode='EXPLICIT_LINK_ONLY'):
    """DOCX는 텍스트·서식을 보존한 링크, PDF는 추가 안내 페이지, TXT는 명시적 링크를 사용합니다."""
    ext = validate_document(name, content)
    if mode == 'WEB_BEACON_HTML':
        return beacon_document(name, url, file_id), 'html', 'text/html'
    mime = {'docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'pdf':'application/pdf', 'txt':'text/plain; charset=utf-8'}[ext]
    if mode == 'DOCX_REMOTE_IMAGE':
        if ext != 'docx':
            raise ValueError('Remote image mode requires DOCX')
        return remote_image_docx(content, url, file_id), ext, mime
    return traced_copy(content, ext, url, file_id), ext, mime


def build_decoy(file_name: str, based_on_hash: str | None = None) -> tuple[Decoy, str]:
    """디코이 레코드와, 파일에 심을 카나리 비콘 URL을 반환."""
    decoy = Decoy(file_name=file_name, based_on_hash=based_on_hash)
    canary_url = f"{settings.canary_base_url.rstrip('/')}/api/canary/{decoy.token_id}"
    return decoy, canary_url
