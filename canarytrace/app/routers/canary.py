"""디코이 파일 생성/배포 + 카나리토큰 비콘 수신."""
from fastapi import APIRouter, Request, Response, Depends, HTTPException, Body

from app.models import CanaryHit, Decoy
from app.services.decoy import build_decoy
from app.services.notifier import notify_slack
from app.store import store

router = APIRouter(prefix="/api", tags=["canary"])


@router.post("/decoys/generate")
async def generate_decoy(file_name: str, based_on_hash: str | None = None) -> dict:
    """유사 기밀 디코이 + 카나리토큰 생성. canary_url을 파일에 심어 배포."""
    decoy, canary_url = build_decoy(file_name, based_on_hash)
    store.add_decoy(decoy)
    return {"decoy": decoy, "canary_url": canary_url}


@router.get("/decoys", response_model=list[Decoy])
async def list_decoys() -> list[Decoy]:
    return store.decoys[::-1]


# 1x1 투명 GIF — 문서가 원격 이미지로 비콘을 당기는 전형적 패턴에 사용
_PIXEL = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c000000000100010000020144003b"
)


@router.get("/canary/{token_id}")
async def canary_beacon(token_id: str, request: Request) -> Response:
    """이전 인메모리 API 호환 코드. 웹 요청 관측만 의미하며 실제 열람/유출은 확정하지 않습니다."""
    from app.config import settings
    from backend.security import observed_ip, scanner_suspected, network_verdict
    if not settings.canary_tracking_enabled:
        raise HTTPException(404, 'Tracking disabled')
    decoy = store.find_decoy_by_token(token_id)
    if decoy is None:
        raise HTTPException(404, 'Unknown token')
    address = observed_ip(request.client.host if request.client else 'UNKNOWN', request.headers.get('x-forwarded-for'), settings.trusted_proxy_list)
    verdict = network_verdict(address, settings.corporate_network_list, scanner=scanner_suspected(request.method, request.headers.get('user-agent','')))

    hit = CanaryHit(
        token_id=token_id,
        opener_ip=address,
        user_agent=request.headers.get("user-agent"),
        extra={'network_verdict': verdict, 'event_confidence':'CONFIRMED_BEACON_REQUEST', 'human_read_confirmed':False},
    )
    store.add_canary_hit(hit)

    if decoy is not None:
        decoy.triggered = True
        decoy.trigger_count += 1
        if verdict == 'EXTERNAL_ACCESS' and settings.canary_external_alerts:
            await notify_slack(f"[CanaryTrace] 외부 웹 요청 관측: {decoy.file_name}; IP={hit.opener_ip}. 실제 열람·유출·PC 위치는 미확정입니다.")

    # 표준 이미지 응답입니다. 문서에는 기업 보안 시험 표시가 포함됩니다.
    return Response(content=_PIXEL, media_type="image/gif")


def install_persistent_routes(app, *, session, admin, security_user, limiter, blob_dir, integrity_key, issue_token):
    """기존 /api/decoys 경로를 중앙 SQLite·인증·감사에 연결하는 운영용 라우터입니다."""
    import hashlib
    import hmac
    import uuid
    from fastapi.responses import FileResponse
    from backend.db import Record, rows, public, audit
    from backend.security import record_signature
    from app.services.decoy import safe_filename
    api = APIRouter(prefix='/api', tags=['decoys'])

    @api.get('/decoys')
    def list_persistent(account=Depends(security_user), db=Depends(session)):
        # 다운로드 URL에 비밀 토큰이나 내부 파일 경로를 노출하지 않습니다.
        return [public(r) for r in rows(db, 'decoy')]

    @api.post('/decoys/generate')
    def generate_persistent(body: dict | None = Body(default=None), file_name: str | None = None, based_on_hash: str | None = None, approved_test_document: bool = False, account=Depends(admin), db=Depends(session)):
        if body is None:
            source = next((r for r in rows(db, 'file') if r.data['name'] == file_name and (not based_on_hash or based_on_hash in r.data['hashes'])), None)
            if not source:
                raise HTTPException(404, 'Registered source document not found')
            body = {'file_id': source.id, 'approved_test_document': approved_test_document}
        try:
            token = issue_token(body, account, db)
        except ValueError:
            raise HTTPException(422, 'Approved registered source document and valid mode required')
        decoy = db.get(Record, token['decoy_id'])
        return {'decoy': public(decoy), 'download_url': '/api/decoys/' + decoy.id + '/file'}

    @api.get('/decoys/{decoy_id}/file')
    def download(decoy_id: str, account=Depends(admin), db=Depends(session)):
        # 문서 다운로드 권한은 관리자에게만 부여합니다. 감사자는 메타데이터를 조회할 수 있습니다.
        limiter.check('download:' + account.id, 30)
        row = db.get(Record, decoy_id)
        if not row or row.kind != 'decoy':
            raise HTTPException(404, 'Decoy not found')
        token = db.get(Record, row.data['token_id'])
        source = db.get(Record, row.data['file_id'])
        if row.data['tracking_status'] != 'ACTIVE' or not token or not token.data.get('active') or not source or not source.data['active']:
            audit(db, account.id, 'DECOY_DOWNLOAD_DENIED', row.id, file_id=row.data['file_id'])
            db.commit()
            raise HTTPException(403, 'Decoy is inactive')
        def failure(reason):
            audit(db, account.id, 'DECOY_DOWNLOAD_FAILED', row.id, file_id=row.data['file_id'], reason=reason)
            db.commit()
            raise HTTPException(500, 'Document unavailable or integrity check failed')
        if not row.seal or not hmac.compare_digest(row.seal, record_signature(integrity_key, row)) or not token.seal or not hmac.compare_digest(token.seal, record_signature(integrity_key, token)):
            failure('METADATA_INTEGRITY_FAILURE')
        try:
            uuid.UUID(token.id)
            path = (blob_dir / token.id).resolve()
            if not path.is_relative_to(blob_dir.resolve()):
                failure('INVALID_STORAGE_REFERENCE')
            raw = path.read_bytes()
        except (OSError, ValueError):
            failure('MISSING_OR_UNREADABLE_ARTIFACT')
        if hashlib.sha256(raw).hexdigest() != row.data['sha256']:
            failure('ARTIFACT_HASH_MISMATCH')
        audit(db, account.id, 'DECOY_DOWNLOADED', row.id, file_id=row.data['file_id'], sha256=row.data['sha256'])
        db.commit()
        # 검증한 바이트 자체를 반환하여 검증과 재열기 사이의 변경(TOCTOU)을 방지합니다.
        from urllib.parse import quote
        return Response(raw, media_type=row.data['media_type'], headers={'Content-Disposition': "attachment; filename*=UTF-8''" + quote(safe_filename(row.data['file_name'])), 'Cache-Control':'no-store'})

    app.include_router(api)
    return download
