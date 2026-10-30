"""디코이(허니팟) 파일 + 카나리토큰 동적 합성 엔진.

[핵심 역할: 투명한 대체(Transparent Substitution)]
공격자가 원천 접근 금지된 기밀 파일에 접근을 시도했을 때, 실제 기밀은 안전하게 보호하고
공격자가 하려던 접근에 대신 실행/제공되는 정교한 가짜 기밀 문서를 LLM으로 합성합니다.
공격자 입장에서는 "실제로 기밀 파일에 접근/탈취했다"고 완벽하게 착각하게 만들며,
문서 내부에 자연스럽게 심긴 카나리토큰(Canary Beacon)이 열람 시 공격자의 IP/UA를 역추적합니다.
"""

from datetime import datetime
import hashlib
import logging
from pathlib import Path
import random
import uuid

from app.config import settings
from app.models import Decoy

logger = logging.getLogger(__name__)


def decoy_file_path(decoy_id: str) -> Path:
    """업로드되거나 합성된 디코이 파일 저장 위치. 파일명 대신 id를 써서 경로 조작을 막는다."""
    return Path(settings.decoy_store_dir) / decoy_id


def save_decoy_file(content: bytes, file_name: str, based_on_hash: str | None = None) -> Decoy:
    """디코이 파일 바이트를 저장하고, 반출 매칭용 SHA-256을 담은 레코드를 반환."""
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


def build_decoy(file_name: str, based_on_hash: str | None = None) -> tuple[Decoy, str]:
    """디코이 레코드와, 파일에 심을 카나리 비콘 URL을 반환."""
    decoy = Decoy(file_name=Path(file_name).name, based_on_hash=based_on_hash)
    canary_url = f"{settings.canary_base_url.rstrip('/')}/api/canary/{decoy.token_id}"
    return decoy, canary_url


def _generate_synthetic_credentials(token_id: str, project_prefix: str) -> dict[str, str]:
    """실제 서비스에는 무효하지만 표준 정규식(Regex)에 완벽히 걸리는 가상 자격증명 합성."""
    fake_aws_access = f"AKIA{uuid.uuid4().hex[:16].upper()}"
    fake_aws_secret = uuid.uuid4().hex + uuid.uuid4().hex[:8]
    fake_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        f"eyJzdWIiOiJzZWMtb3BzLWFkbWluIiwicHJvamVjdCI6Intwcm9qZWN0X3ByZWZpeH0iLCJjYW5hcnkiOiJ7dG9rZW5faWR9In0."
        f"{hashlib.sha256(token_id.encode()).hexdigest()[:43]}"
    )
    fake_db = f"postgresql://admin_master:P@ssw0rd_{token_id[:6]}@db-internal-prod.{project_prefix}.local:5432/{project_prefix}_db"

    return {
        "aws_access": fake_aws_access,
        "aws_secret": fake_aws_secret,
        "jwt": fake_jwt,
        "db_url": fake_db,
    }


def synthesize_decoy_text(file_name: str, canary_url: str, token_id: str) -> str:
    """공격자가 실제 기밀을 열람했다고 믿도록 LLM 기반으로 진짜 같은 가짜 기밀 문서를 합성."""
    stem = Path(file_name).stem
    parts = stem.split("_")
    project_prefix = f"{parts[0]}_{parts[1]}".lower() if len(parts) >= 2 else parts[0].lower()
    creds = _generate_synthetic_credentials(token_id, project_prefix)

    # 1. Gemini 또는 Anthropic LLM API 연동 (설정된 경우)
    if settings.gemini_api_key:
        try:
            from google import genai
            client = genai.Client(api_key=settings.gemini_api_key)
            prompt = (
                f"You are generating an authentic-looking internal corporate confidential document for project '{project_prefix}'.\n"
                f"The document filename is '{file_name}'.\n"
                f"It MUST include realistic infrastructure secrets and embed this telemetry sync URL: {canary_url}\n"
                f"Include fake AWS key: {creds['aws_access']} and JWT: {creds['jwt']}\n"
                f"Output only the document content without meta-explanations."
            )
            resp = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            if resp.text:
                return resp.text.strip()
        except Exception as e:
            logger.warning("Gemini LLM decoy synthesis fallback: %s", e)

    elif settings.anthropic_api_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
            prompt = (
                f"공격자가 실제로 기밀 파일에 접근했다고 믿도록 프로젝트 '{project_prefix}'의 기밀 문서 '{file_name}'를 합성하세요.\n"
                f"다음 헬스체크 웹훅 URL을 설정 내에 자연스럽게 임베딩하세요: {canary_url}\n"
                f"가짜 AWS 키({creds['aws_access']})와 DB 설정({creds['db_url']})을 포함해 한국어/영문이 섞인 현실적인 내부 문서로 작성하세요."
            )
            msg = client.messages.create(
                model=settings.ai_model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )
            if msg.content and hasattr(msg.content[0], "text"):
                return msg.content[0].text.strip()
        except Exception as e:
            logger.warning("Anthropic LLM decoy synthesis fallback: %s", e)

    # 2. Resilient Rule/Template Synthesis Engine (오프라인/PoC에서도 100% 동작 보장)
    return (
        f"======================================================================\n"
        f"CONFIDENTIAL & RESTRICTED - {project_prefix.upper()} CORE SYSTEM ASSET\n"
        f"Document: {Path(file_name).name}\n"
        f"Classification: Level 4 Strictly Confidential (DevSecOps Operations Only)\n"
        f"Last Audit: 2026-10-18 09:22:15 KST\n"
        f"======================================================================\n\n"
        f"## 1. Production Cloud Environment Access\n"
        f"[AWS IAM Master Deployment Role]\n"
        f"AWS_ACCESS_KEY_ID={creds['aws_access']}\n"
        f"AWS_SECRET_ACCESS_KEY={creds['aws_secret']}\n"
        f"AWS_DEFAULT_REGION=ap-northeast-2\n\n"
        f"## 2. Infrastructure Synchronization Webhook\n"
        f"# Internal cluster rotation telemetry beacon (triggered upon credential load):\n"
        f"CONFIG_ROTATION_BEACON_URL=\"{canary_url}\"\n\n"
        f"## 3. Disaster Recovery & Emergency Admin JWT\n"
        f"BEARER_AUTH_TOKEN=\"{creds['jwt']}\"\n\n"
        f"## 4. Internal Database Master Connection\n"
        f"PRIMARY_DB_CONNECTION=\"{creds['db_url']}\"\n\n"
        f"NOTICE: This document contains proprietary intellectual assets.\n"
        f"Unauthorized inspection, copying, moving, or distribution is monitored.\n"
    )


def synthesize_transparent_decoy(file_name: str, based_on_hash: str | None = None) -> tuple[Decoy, str]:
    """공격자의 접근 대상 파일과 외형이 동일하거나 유사한 디코이를 LLM으로 합성하고,

    파일 바이트를 디코이 저장소에 영구 보관한 뒤 레코드를 반환합니다.
    """
    clean_name = Path(file_name).name
    # lookalike 파일명 보정 (필요시 확장자 유지)
    decoy, canary_url = build_decoy(clean_name, based_on_hash)

    # 문서 본문 합성
    content_text = synthesize_decoy_text(clean_name, canary_url, decoy.token_id)
    content_bytes = content_text.encode("utf-8")

    # 파일 시스템에 실제 디코이 파일로 저장 및 sha256 / size 동기화
    decoy.sha256 = hashlib.sha256(content_bytes).hexdigest()
    decoy.size = len(content_bytes)

    target_path = decoy_file_path(decoy.id)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(content_bytes)

    return decoy, canary_url
