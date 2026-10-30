import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import uuid
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv

from .db import Record, add, audit, connect, now, public, rows
from .documents import LIMIT, traced_copy, validate_document, beacon_document
from . import notifications
from .analysis import analyze_event
from .security import RateLimiter, digest, in_networks, observed_ip, password_hash, password_ok, process_classification, scanner_suspected, record_signature, network_verdict
from app.config import Settings
from app.services.decoy import render_decoy, safe_filename

ROOT = Path(__file__).resolve().parents[1]
WARNING = '토큰 URL 접근 또는 파일 접근 확인이며, 실제 사용자 열람·정보 유출 확정은 아닙니다.'


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


class NewUser(Login):
    password: str = Field(min_length=12, max_length=200)
    role: Literal['admin', 'auditor', 'viewer', 'recipient']


class NewToken(BaseModel):
    file_id: str
    approved_test_document: Literal[True]
    mode: Literal['EXPLICIT_LINK_ONLY', 'WEB_BEACON_HTML', 'DOCX_REMOTE_IMAGE'] = 'EXPLICIT_LINK_ONLY'


class NewDevice(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: Literal['WINDOWS_AGENT', 'SMTP_GATEWAY'] = 'WINDOWS_AGENT'


class Policy(BaseModel):
    allowed_networks: list[str] = Field(default_factory=lambda: ['127.0.0.0/8', '::1/128'], max_length=100)
    retention_days: int = Field(default=30, ge=1, le=3650)
    correlation_hours: int = Field(default=48, ge=1, le=168)
    canary_external_alerts: bool = True
    canary_tracking_enabled: bool = True
    blocked_networks: list[str] = Field(default_factory=list, max_length=100)

    @field_validator('allowed_networks', 'blocked_networks')
    @classmethod
    def cidrs(cls, v):
        return [str(ipaddress.ip_network(n)) for n in v]


class EndpointEvent(BaseModel):
    file_id: str
    distribution_id: str | None = None
    issuance_id: str | None = None
    sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    record_id: int = Field(ge=1)
    occurred_at: datetime
    pc_name: str = Field(min_length=1, max_length=200)
    windows_user: str = Field(min_length=1, max_length=300)
    process: str = Field(min_length=1, max_length=1000)
    process_id: str = Field(max_length=30)
    object_path: str = Field(min_length=1, max_length=2000)
    access_mask: int = Field(ge=0, le=0xFFFFFFFF)
    source_type: Literal['WINDOWS_SECURITY_4663']
    local_ip: str = Field(default='UNKNOWN', max_length=100)
    windows_sid: str = Field(default='UNKNOWN', max_length=200)
    storage_type: Literal['LOCAL', 'REMOVABLE', 'USB', 'NETWORK', 'UNKNOWN'] = 'UNKNOWN'
    volume_id: str | None = Field(default=None, max_length=200)
    usb_device_id: str | None = Field(default=None, max_length=300)
    detected_at: datetime | None = None

    @field_validator('occurred_at')
    @classmethod
    def aware(cls, v):
        if v.tzinfo is None:
            raise ValueError('Timestamp must include timezone')
        if v > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError('Timestamp is in the future')
        return v.astimezone(timezone.utc)


class Movement(BaseModel):
    file_id: str | None = None
    distribution_id: str | None = None
    issuance_id: str | None = None
    sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    external_id: str = Field(min_length=1, max_length=200)
    occurred_at: datetime
    channel: Literal['USB', 'EMAIL']
    source: str = Field(min_length=1, max_length=2000)
    destination: str = Field(min_length=1, max_length=2000)
    evidence_type: Literal['APPROVED_COPY_TOOL', 'SMTP_AUDIT_LOG']
    evidence_reference: str = Field(min_length=1, max_length=1000)
    usb_device_id: str | None = Field(default=None, max_length=300)
    volume_id: str | None = Field(default=None, max_length=200)
    copy_observed: bool = False
    stage: Literal['FILE_COPIED_TO_USB', 'EMAIL_ATTACHMENT_SENT', 'EMAIL_DELIVERED', 'FILE_DOWNLOADED'] | None = None
    message_id: str | None = Field(default=None, max_length=500)
    recipient_device_id: str | None = Field(default=None, max_length=200)

    _aware = field_validator('occurred_at')(EndpointEvent.aware.__func__)


class Lineage(BaseModel):
    file_id: str
    previous_hash: str = Field(pattern=r'^[a-f0-9]{64}$')
    new_hash: str = Field(pattern=r'^[a-f0-9]{64}$')
    record_id: int = Field(ge=1)
    occurred_at: datetime
    object_path: str = Field(max_length=2000)
    file_identity: str = Field(min_length=1, max_length=200)
    evidence_type: Literal['OBSERVED_4663_WRITE_SAME_FILE_ID']
    _aware = field_validator('occurred_at')(EndpointEvent.aware.__func__)


class Diagnostic(BaseModel):
    external_id: str = Field(min_length=1, max_length=200)
    code: Literal['COLLECTION_FAILED', 'UNRESOLVED_ACCESS', 'AUDIT_LOG_RESET', 'AUDIT_LOG_GAP', 'DELIVERY_REJECTED']
    detail: str = Field(max_length=2000)
    occurred_at: datetime
    _aware = field_validator('occurred_at')(EndpointEvent.aware.__func__)


def create_app(settings=None):
    load_dotenv(ROOT / '.env', override=False)
    settings = settings or {}
    runtime = Path(settings.get('runtime', os.getenv('DATAGUARD_RUNTIME', ROOT / '.runtime')))
    runtime.mkdir(parents=True, exist_ok=True)
    stored = json.loads((runtime / 'settings.json').read_text('utf-8')) if (runtime / 'settings.json').exists() else {}
    cfg = {**stored, **settings}
    env_settings = Settings()
    admin_password = cfg.get('admin_password') or os.getenv('DATAGUARD_ADMIN_PASSWORD')
    if not admin_password or len(admin_password) < 12:
        raise RuntimeError('Run scripts/setup.py first or set a strong DATAGUARD_ADMIN_PASSWORD')
    base_url = cfg.get('public_base_url', 'https://localhost:8443').rstrip('/')
    parsed = urlparse(base_url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.query or parsed.fragment or parsed.username or parsed.path not in ('', '/'):
        raise RuntimeError('public_base_url must be an HTTPS origin')
    trusted = [str(ipaddress.ip_network(n)) for n in cfg.get('trusted_proxies', env_settings.trusted_proxy_list)]
    integrity_key = cfg.get('integrity_key') or os.getenv('DATAGUARD_INTEGRITY_KEY')
    if not integrity_key or len(integrity_key) < 32:
        raise RuntimeError('DATAGUARD_INTEGRITY_KEY must contain at least 32 characters; run setup')
    Session, engine = connect(runtime / 'dataguard.db', integrity_key)
    blob_dir = runtime / 'files'
    blob_dir.mkdir(exist_ok=True)
    webhook = cfg.get('slack_webhook_url', os.getenv('SLACK_WEBHOOK_URL', ''))
    notifications.validate_webhook(webhook)
    @asynccontextmanager
    async def lifespan(application):
        stop = asyncio.Event()
        task = asyncio.create_task(notifications.worker(Session, webhook, stop))
        yield
        stop.set()
        await task
    app = FastAPI(title='DataGuard · CanaryTrace', version='1.0.0', lifespan=lifespan)
    app.state.Session = Session
    app.state.engine = engine
    app.state.runtime = runtime
    limiter = RateLimiter()

    with Session.begin() as db:
        if not db.get(Record, 'admin'):
            add(db, 'user', {'username': 'admin', 'password': password_hash(admin_password), 'role': 'admin'}, id='admin')
        if not db.get(Record, 'policy'):
            add(db, 'policy', Policy(allowed_networks=env_settings.corporate_network_list, canary_external_alerts=env_settings.canary_external_alerts, canary_tracking_enabled=env_settings.canary_tracking_enabled).model_dump(), id='policy')
        else:
            saved = db.get(Record, 'policy')
            saved.data = Policy(**saved.data).model_dump()

    def session():
        with Session() as db:
            yield db

    def ip(request):
        return observed_ip(request.client.host if request.client else 'UNKNOWN', request.headers.get('x-forwarded-for'), trusted)

    def user(request: Request, db=Depends(session)):
        auth = request.headers.get('authorization', '')
        key = auth[7:] if auth.startswith('Bearer ') else ''
        token = db.get(Record, 'session:' + digest(key)) if key else None
        if not token or token.data['expires_at'] <= now():
            raise HTTPException(401, 'Administrator login required')
        account = db.get(Record, token.data['user_id'])
        if not account or account.kind != 'user':
            raise HTTPException(401, 'Invalid account')
        if account.data['role'] == 'recipient' and not (request.url.path.startswith('/api/distributions/') and request.url.path.endswith('/download')) and request.url.path != '/api/logout':
            raise HTTPException(403, 'Recipient accounts may download granted distributions only')
        return account

    def admin(account=Depends(user)):
        if account.data['role'] != 'admin':
            raise HTTPException(403, 'Admin role required')
        return account

    def security_user(account=Depends(user)):
        if account.data['role'] not in {'admin', 'auditor'}:
            raise HTTPException(403, 'Security role required')
        return account

    async def device(request: Request, db=Depends(session)):
        # 장치 키는 서버에서 해시로 조회합니다. 쓰기 요청은 본문·경로·시각의 서명도 검사합니다.
        key = request.headers.get('x-device-key', '')
        row = db.scalar(select(Record).where(Record.kind == 'device', Record.dedup_key == 'device:' + digest(key))) if key else None
        if not row or not row.data['active']:
            raise HTTPException(401, 'Authenticated device required')
        limiter.check('device:' + row.id, 600)
        if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            stamp = request.headers.get('x-event-timestamp', '')
            signature = request.headers.get('x-event-signature', '')
            try:
                if abs(time.time() - int(stamp)) > 300:
                    raise ValueError('Expired request')
            except ValueError:
                raise HTTPException(401, 'Fresh signed request required')
            material = stamp.encode() + b'\n' + request.url.path.encode() + b'\n' + await request.body()
            expected = hmac.new(bytes.fromhex(digest(key)), material, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise HTTPException(401, 'Invalid event signature')
        return row

    def get_file(db, file_id):
        row = db.get(Record, file_id)
        if not row or row.kind != 'file':
            raise HTTPException(404, 'File not found')
        return row

    def check_hash(db, file_id, sha):
        row = get_file(db, file_id)
        if sha not in row.data['hashes'] or not row.data['active'] or row.data['classification'] not in {'CONFIDENTIAL', 'RESTRICTED'}:
            raise HTTPException(422, 'Hash not registered for active confidential file')
        return row

    @app.middleware('http')
    async def headers(request: Request, call_next):
        if request.url.scheme != 'https' and not cfg.get('allow_http_loopback', False):
            return HTMLResponse('HTTPS required', status_code=400)
        if request.url.scheme != 'https' and not in_networks(request.client.host, ['127.0.0.0/8', '::1/128']):
            return HTMLResponse('Local development HTTP only', status_code=400)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
        if request.url.scheme == 'https':
            response.headers['Strict-Transport-Security'] = 'max-age=86400'
        return response

    @app.get('/api/health')
    def health():
        return {'status': 'ok', 'service': 'DataGuard', 'evidence_warning': WARNING}

    @app.post('/api/login')
    def login(body: Login, request: Request, db=Depends(session)):
        limiter.check('login:' + ip(request), 10)
        account = next((u for u in rows(db, 'user') if u.data['username'] == body.username), None)
        valid = password_ok(body.password, account.data['password'] if account else app.state.dummy_hash)
        if not account or not valid:
            audit(db, 'anonymous', 'LOGIN_FAILED', 'auth')
            db.commit()
            raise HTTPException(401, 'Invalid credentials')
        secret = secrets.token_urlsafe(32)
        add(db, 'session', {'user_id': account.id, 'expires_at': (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()}, id='session:' + digest(secret))
        audit(db, account.id, 'LOGIN', account.id)
        db.commit()
        return {'access_token': secret, 'role': account.data['role'], 'username': account.data['username']}

    app.state.dummy_hash = password_hash(secrets.token_urlsafe(32))

    @app.post('/api/logout')
    def logout(request: Request, account=Depends(user), db=Depends(session)):
        db.delete(db.get(Record, 'session:' + digest(request.headers['authorization'][7:])))
        audit(db, account.id, 'LOGOUT', account.id)
        db.commit()
        return {'ok': True}

    @app.post('/api/users')
    def create_user(body: NewUser, account=Depends(admin), db=Depends(session)):
        if any(u.data['username'] == body.username for u in rows(db, 'user')):
            raise HTTPException(409, 'Username exists')
        row = add(db, 'user', {'username': body.username, 'password': password_hash(body.password), 'role': body.role})
        audit(db, account.id, 'USER_CREATED', row.id)
        db.commit()
        return {'id': row.id, 'role': body.role}

    @app.get('/api/files')
    def files(account=Depends(user), db=Depends(session)):
        return [public(r) for r in rows(db, 'file')]

    @app.post('/api/files')
    async def upload(file: UploadFile = File(...), classification: Literal['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'] = Form('CONFIDENTIAL'), account=Depends(admin), db=Depends(session)):
        # 파일명이 바뀌어도 내용이 같으면 같은 SHA-256입니다. 일반 등급은 수집 정책에서 제외합니다.
        content = await file.read(LIMIT + 1)
        name = safe_filename(file.filename or 'file')
        if len(name) > 200:
            raise HTTPException(422, 'Filename too long')
        try:
            ext = validate_document(name, content)
        except Exception as exc:
            raise HTTPException(422, 'Invalid, unsupported, or oversized document') from exc
        sha = hashlib.sha256(content).hexdigest()
        if any(sha in r.data['hashes'] for r in rows(db, 'file')):
            raise HTTPException(409, 'Identical content already registered; use its file ID')
        tracked = classification in {'CONFIDENTIAL', 'RESTRICTED'}
        row = add(db, 'file', {'name': name, 'file_name': name, 'classification': classification, 'owner_id': account.id, 'extension': ext, 'sha256': sha, 'file_hash': sha, 'hashes': [sha], 'size': len(content), 'active': True, 'tracking_status': 'TRACKED' if tracked else 'EXCLUDED_BY_POLICY'})
        row.data = {**row.data, 'file_id': row.id}
        (blob_dir / row.id).write_bytes(content)
        audit(db, account.id, 'FILE_REGISTERED', row.id, sha256=sha)
        if tracked:
            # 전체 등록 기밀문서에 토큰을 자동 연결합니다. 원본은 보존하고 배포용 사본에 삽입합니다.
            token(NewToken(file_id=row.id, approved_test_document=True), account, db)
        db.commit()
        return public(row)

    @app.get('/api/files/{file_id}/original')
    def original(file_id: str, account=Depends(admin), db=Depends(session)):
        row = get_file(db, file_id)
        audit(db, account.id, 'ORIGINAL_DOWNLOADED', row.id)
        db.commit()
        return FileResponse(blob_dir / row.id, filename=row.data['name'], media_type='application/octet-stream')

    @app.post('/api/files/{file_id}/deactivate')
    def deactivate_file(file_id: str, account=Depends(admin), db=Depends(session)):
        row = get_file(db, file_id)
        row.data = {**row.data, 'active': False, 'tracking_status': 'INACTIVE'}
        for token in rows(db, 'token'):
            if token.data['file_id'] == file_id:
                token.data = {**token.data, 'active': False}
        audit(db, account.id, 'FILE_DEACTIVATED', file_id)
        db.commit()
        return {'ok': True}

    @app.get('/api/tokens')
    def tokens(account=Depends(admin), db=Depends(session)):
        return [public(r) for r in rows(db, 'token')]

    @app.post('/api/tokens')
    def token(body: NewToken, account=Depends(admin), db=Depends(session)):
        # 관리자가 승인한 테스트 문서만 사본을 생성합니다. 원본에는 실행 코드·매크로를 넣지 않습니다.
        file = get_file(db, body.file_id)
        if not file.data['active']:
            raise HTTPException(409, 'File inactive')
        secret = secrets.token_urlsafe(32)
        if body.mode == 'DOCX_REMOTE_IMAGE' and file.data['extension'] != 'docx':
            raise HTTPException(422, 'Remote image mode requires DOCX')
        url = base_url + ('/b/' if body.mode in {'WEB_BEACON_HTML', 'DOCX_REMOTE_IMAGE'} else '/t/') + secret
        row = add(db, 'token', {'file_id': file.id, 'active': True, 'url': url, 'mode': body.mode, 'approved_test_document': True, 'approved_by': account.id}, dedup_key='token:' + digest(secret))
        data, document_format, media_type = render_decoy((blob_dir / file.id).read_bytes(), file.data['name'], url, file.id, body.mode)
        sha = hashlib.sha256(data).hexdigest()
        (blob_dir / row.id).write_bytes(data)
        row.data = {**row.data, 'artifact_sha256': sha}
        decoy = add(db, 'decoy', {'file_id': file.id, 'token_id': row.id, 'file_name': 'tracked-' + file.data['name'] + ('.html' if document_format == 'html' else ''), 'document_format': document_format, 'classification': file.data['classification'], 'issued_by': account.id, 'tracking_status': 'ACTIVE', 'sha256': sha, 'media_type': media_type})
        decoy.data = {**decoy.data, 'decoy_id': decoy.id}
        row.data = {**row.data, 'decoy_id': decoy.id}
        file.data = {**file.data, 'hashes': file.data['hashes'] + [sha], 'token_provisioned': True}
        add(db, 'lineage', {'file_id': file.id, 'previous_hash': file.data['sha256'], 'new_hash': sha, 'evidence_type': 'SERVER_GENERATED_APPROVED_TOKEN_COPY', 'occurred_at': now(), 'token_id': row.id})
        audit(db, account.id, 'TOKEN_ISSUED', row.id, file_id=file.id)
        audit(db, account.id, 'DECOY_ISSUED', decoy.id, file_id=file.id)
        db.commit()
        return public(row)

    @app.get('/api/tokens/{token_id}/download')
    def download(token_id: str, account=Depends(admin), db=Depends(session)):
        row = db.get(Record, token_id)
        if not row or row.kind != 'token':
            raise HTTPException(404, 'Token not found')
        return decoy_download(row.data['decoy_id'], account, db)

    @app.post('/api/tokens/{token_id}/deactivate')
    def deactivate(token_id: str, account=Depends(admin), db=Depends(session)):
        row = db.get(Record, token_id)
        if not row or row.kind != 'token':
            raise HTTPException(404, 'Token not found')
        row.data = {**row.data, 'active': False}
        if row.data.get('decoy_id'):
            decoy = db.get(Record, row.data['decoy_id'])
            if decoy:
                decoy.data = {**decoy.data, 'tracking_status': 'INACTIVE'}
        audit(db, account.id, 'TOKEN_DEACTIVATED', token_id)
        db.commit()
        return {'ok': True}

    @app.api_route('/t/{secret}', methods=['GET', 'HEAD', 'POST'])
    @app.api_route('/b/{secret}', methods=['GET', 'HEAD'])
    @app.get('/api/canary/{secret}')
    def access(secret: str, request: Request, db=Depends(session)):
        # 웹 요청은 관측 사실이지만 파일 열람·실제 사용자·PC·위치를 확정하는 증거는 아닙니다.
        address = ip(request)
        limiter.check('token:' + address, 120)
        row = db.scalar(select(Record).where(Record.kind == 'token', Record.dedup_key == 'token:' + digest(secret)))
        if not row or not row.data['active']:
            audit(db, 'public', 'TOKEN_ACCESS_REJECTED', row.id if row else 'UNKNOWN', reason='inactive' if row else 'unknown')
            db.commit()
            raise HTTPException(404, 'Resource not available')
        policy = db.get(Record, 'policy').data
        if not policy.get('canary_tracking_enabled', True):
            raise HTTPException(404, 'Tracking is disabled by policy')
        ua = request.headers.get('user-agent', '')[:1000]
        scan = scanner_suspected(request.method, ua)
        internal = in_networks(address, policy['allowed_networks'])
        network = network_verdict(address, policy['allowed_networks'], scanner=scan, blocked=in_networks(address, policy.get('blocked_networks', [])))
        verdict = 'INTERNAL_ALLOWED' if network == 'INTERNAL_ACCESS' else ('EXTERNAL_SUSPECTED' if network in {'EXTERNAL_ACCESS','POLICY_VIOLATION'} else network)
        file = get_file(db, row.data['file_id'])
        event = add(db, 'event', {'event_id': str(uuid.uuid4()), 'token_id': row.id, 'file_id': file.id, 'file_name': file.data['name'], 'classification': file.data['classification'], 'occurred_at': now(), 'received_at': now(), 'observed_public_ip': address, 'ip_scope': 'PUBLIC' if address != 'UNKNOWN' and ipaddress.ip_address(address).is_global else 'NON_PUBLIC_OR_UNKNOWN', 'user_agent': ua, 'request_method': request.method, 'source_type': 'TOKEN_URL', 'event_confidence': 'URL_ACCESS_CONFIRMED', 'activity': 'AUTOMATED_SCAN_SUSPECTED' if scan else 'URL_ACCESS_ONLY', 'policy_verdict': verdict, 'risk_score': 20 if scan else (10 if internal else 70), 'route': 'UNKNOWN', 'human_read_confirmed': False, 'warning': WARNING})
        audit(db, 'public', 'EVENT_RECORDED', event.data['event_id'], record_id=event.id)
        beacon = request.url.path.startswith(('/b/', '/api/canary/'))
        event.data = {**event.data, 'source_type': 'WEB_BEACON' if beacon else 'TOKEN_URL', 'activity': 'AUTOMATED_SCAN_SUSPECTED' if scan else ('IMAGE_REQUEST_ONLY' if beacon else 'URL_ACCESS_ONLY'), 'status': 'REVIEW' if scan else ('NORMAL' if internal else 'POLICY_REVIEW')}
        event.data = {**event.data, 'analysis': analyze_event(event.data, []), 'decoy_id': row.data.get('decoy_id'), 'network_verdict': network, 'event_confidence': 'CONFIRMED_BEACON_REQUEST', 'applied_policy': {'allowed_networks': policy['allowed_networks'], 'external_alerts': policy.get('canary_external_alerts', True)}, 'classification_reason': 'Request method/user-agent scanner heuristic' if scan else 'Server-observed IP and configured CIDR policy; identity/location not established'}
        event.data = {**event.data, 'distribution_id': row.data.get('distribution_id'), 'issuance_id': row.data.get('issuance_id'), 'evidence_origin': 'RECEIVED_HTTP_REQUEST', 'network_caveat': 'VPN/NAT/proxy may affect classification; IP is not a person or PC identity'}
        event.data = {**event.data, 'request_path': request.url.path, 'scanner_suspected': scan, 'document_mode': row.data['mode']}
        if network in {'EXTERNAL_ACCESS', 'POLICY_VIOLATION'} and policy.get('canary_external_alerts', True):
            notifications.enqueue(db, event.data, bool(webhook))
            add(db, 'alert', {'file_id': file.id, 'decoy_id': row.data.get('decoy_id'), 'distribution_id': row.data.get('distribution_id'), 'issuance_id': row.data.get('issuance_id'), 'event_id': event.data['event_id'], 'type': network, 'status': 'OPEN', 'reason': 'External or blocked network beacon request; exfiltration not established'})
        elif network == 'UNKNOWN_NETWORK':
            audit(db, 'public', 'NETWORK_CLASSIFICATION_FAILED', event.data['event_id'], file_id=file.id)
        db.commit()
        if beacon:
            if row.data['mode'] == 'DOCX_REMOTE_IMAGE':
                from .documents import tracking_png
                return Response(tracking_png(), media_type='image/png')
            return Response(bytes.fromhex('47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b'), media_type='image/gif')
        return HTMLResponse('<!doctype html><html lang="ko"><meta charset="utf-8"><title>CanaryTrace</title><p>확인 링크 요청이 기록되었습니다. 이 기록은 파일 열람 또는 유출을 확정하지 않습니다.</p></html>')

    @app.get('/api/notifications')
    def notification_status(account=Depends(security_user), db=Depends(session)):
        return {'configured': bool(webhook), 'records': [{k: v for k, v in public(r).items() if k != 'payload'} for r in rows(db, 'notification')][:200]}

    # 기존 라우터 파일을 재사용하여 디코이 다운로드와 중앙 서버를 같은 인증/DB에 연결합니다.
    from app.routers.canary import install_persistent_routes
    decoy_download = install_persistent_routes(app, session=session, admin=admin, security_user=security_user, limiter=limiter, blob_dir=blob_dir, integrity_key=integrity_key, issue_token=lambda body, account, db: token(NewToken(**body), account, db))
    from .distributions import install_distribution_routes, issuance_for_hash
    install_distribution_routes(app, session=session, admin=admin, user=user, security_user=security_user, blob_dir=blob_dir, integrity_key=integrity_key, base_url=base_url, limiter=limiter, observed_ip=ip)
    from .telemetry import install_telemetry, artifact_ids
    install_telemetry(app, session=session, device=device, security_user=security_user, observed_ip=ip)
    from .sources import install_sources
    install_sources(app, session=session, admin=admin, register_file=upload)

    @app.get('/api/alerts')
    def alerts(account=Depends(security_user), db=Depends(session)):
        return [public(r) for r in rows(db, 'alert')][:500]

    @app.post('/api/events/{event_id}/investigation')
    def investigate(event_id: str, body: dict, account=Depends(security_user), db=Depends(session)):
        event = next((r for r in rows(db, 'event') if r.data['event_id']==event_id), None)
        if not event:
            raise HTTPException(404, 'Event not found')
        if body.get('status') not in {'OPEN','BENIGN','ESCALATED','RESOLVED'} or not isinstance(body.get('note'),str) or not 1 <= len(body['note']) <= 2000:
            raise HTTPException(422, 'Valid investigation status and note required')
        row = add(db, 'investigation', {'event_id':event_id,'file_id':event.data['file_id'],'status':body['status'],'note':body['note'],'reviewed_by':account.id})
        audit(db, account.id, 'EVENT_INVESTIGATED', event_id, file_id=event.data['file_id'], investigation_id=row.id)
        db.commit()
        return public(row)

    @app.get('/api/files/{file_id}/timeline')
    def timeline(file_id: str, account=Depends(security_user), db=Depends(session)):
        file = get_file(db, file_id)
        result = [{'kind':'registration', **public(file)}]
        for kind in ['decoy','lineage','event','movement','alert','investigation','audit']:
            result.extend({'kind':kind, **public(r)} for r in rows(db, kind) if r.data.get('file_id')==file_id or (kind=='audit' and r.data.get('target_id')==file_id))
        return sorted(result, key=lambda r:r['created_at'])

    @app.post('/api/devices')
    def enroll(body: NewDevice, account=Depends(admin), db=Depends(session)):
        secret = secrets.token_urlsafe(40)
        row = add(db, 'device', {'name': body.name, 'kind': body.kind, 'active': True, 'last_seen': None}, dedup_key='device:' + digest(secret))
        audit(db, account.id, 'DEVICE_ENROLLED', row.id)
        db.commit()
        return {**public(row), 'device_key': secret}

    @app.get('/api/devices')
    def devices(account=Depends(admin), db=Depends(session)):
        return [public(r) for r in rows(db, 'device')]

    @app.post('/api/devices/{device_id}/revoke')
    def revoke(device_id: str, account=Depends(admin), db=Depends(session)):
        row = db.get(Record, device_id)
        if not row or row.kind != 'device':
            raise HTTPException(404, 'Device not found')
        row.data = {**row.data, 'active': False}
        audit(db, account.id, 'DEVICE_REVOKED', device_id)
        db.commit()
        return {'ok': True}

    @app.get('/api/agent/manifest')
    def manifest(endpoint=Depends(device), db=Depends(session)):
        endpoint.data = {**endpoint.data, 'last_seen': now()}
        db.commit()
        return {'policy': db.get(Record, 'policy').data, 'files': [{'file_id': r.id, 'name': r.data['name'], 'hashes': r.data['hashes'], 'classification': r.data['classification']} for r in rows(db, 'file') if r.data['active'] and r.data['classification'] in {'CONFIDENTIAL', 'RESTRICTED'}], 'issuances': [{k: r.data[k] for k in ['file_id', 'file_hash', 'distribution_id', 'issuance_id']} for r in rows(db, 'issuance')], 'distributions': [{'distribution_id': r.id, 'sha256': r.data['sha256'], 'files': r.data['files']} for r in rows(db, 'distribution')]}

    @app.post('/api/agent/events')
    def endpoint_event(body: EndpointEvent, request: Request, endpoint=Depends(device), db=Depends(session)):
        # 4663 ReadData와 등록 해시를 확인합니다. 재전송된 같은 감사 이벤트는 한 번만 저장합니다.
        if endpoint.data['kind'] != 'WINDOWS_AGENT':
            raise HTTPException(403, 'Windows agent required')
        file = check_hash(db, body.file_id, body.sha256)
        issuance = issuance_for_hash(db, file.id, body.sha256)
        if (body.distribution_id and body.distribution_id != issuance.get('distribution_id')) or (body.issuance_id and body.issuance_id != issuance.get('issuance_id')):
            raise HTTPException(422, 'Issuance IDs do not match registered artifact hash')
        if not body.access_mask & 1:
            raise HTTPException(422, 'ReadData access required')
        key = f'endpoint:{endpoint.id}:{body.record_id}:{body.occurred_at.isoformat()}'
        existing = db.scalar(select(Record).where(Record.dedup_key == key))
        if existing:
            return {'event_id': existing.data['event_id'], 'duplicate': True}
        event_id = str(uuid.uuid4())
        data = body.model_dump(mode='json')
        data.update(event_id=event_id, token_id=None, file_name=file.data['name'], classification=file.data['classification'], device_id=endpoint.id, received_at=now(), observed_public_ip=ip(request), user_agent=request.headers.get('user-agent', '')[:1000], request_method=request.method, event_confidence='AUTHENTICATED_DEVICE_FILE_ACCESS_REPORT', policy_verdict='MANAGED_FILE_ACCESS', activity=process_classification(body.process), risk_score=25, route='UNKNOWN', human_read_confirmed=False, warning=WARNING)
        data.update(device_name=body.pc_name, process_name=body.process, file_path=body.object_path, access_type='READ_DATA', detected_at=data.get('detected_at') or now(), ip_scope='PUBLIC' if ip(request) != 'UNKNOWN' and ipaddress.ip_address(ip(request)).is_global else 'NON_PUBLIC_OR_UNKNOWN')
        outside = not in_networks(ip(request), db.get(Record, 'policy').data['allowed_networks'])
        data['policy_verdict'] = 'EXTERNAL_SUSPECTED' if outside else 'MANAGED_FILE_ACCESS'
        data['status'] = 'POLICY_REVIEW' if outside else ('REVIEW' if data['activity'] != 'INTERACTIVE_PROCESS_CANDIDATE' else 'CONFIDENTIAL_ACCESS')
        data['analysis'] = analyze_event(data, [r.data for r in rows(db, 'event')[:1000]])
        data['event_confidence'] = 'CONFIRMED_FILE_ACCESS'
        data['network_verdict'] = network_verdict(ip(request), db.get(Record, 'policy').data['allowed_networks'])
        data['decoy_id'] = next((d.id for d in rows(db, 'decoy') if d.data['file_id']==file.id and d.data['sha256']==body.sha256), None)
        data.update(issuance)
        data['evidence_origin'] = 'AUTHENTICATED_WINDOWS_AGENT'
        from .security import process_category
        data['process_category'] = process_category(body.process)
        data['network_caveat'] = 'VPN/NAT/proxy may affect classification; device reports are trusted only within the enrolled endpoint boundary'
        policy = db.get(Record, 'policy').data
        if issuance and data['network_verdict'] == 'EXTERNAL_ACCESS' and policy.get('canary_external_alerts', True):
            notifications.enqueue(db, data, bool(webhook))
            add(db, 'alert', {**issuance, 'event_id': event_id, 'type': 'EXTERNAL_ACCESS', 'status': 'OPEN', 'reason': 'Managed file access from outside allowed networks; exfiltration not established'})
        data['risk_score'] = data['analysis']['risk_score']
        row = add(db, 'event', data, dedup_key=key)
        endpoint.data = {**endpoint.data, 'last_seen': now()}
        audit(db, endpoint.id, 'EVENT_RECORDED', event_id, record_id=row.id)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            existing = db.scalar(select(Record).where(Record.dedup_key == key))
            if existing:
                return {'event_id': existing.data['event_id'], 'duplicate': True}
            raise
        return {'event_id': event_id, 'duplicate': False}

    @app.post('/api/agent/lineage')
    def lineage(body: Lineage, endpoint=Depends(device), db=Depends(session)):
        # 해시 유사성으로 계보를 만들지 않습니다. 동일 파일 ID에서 관측한 쓰기 사건을 근거로 연결합니다.
        if endpoint.data['kind'] != 'WINDOWS_AGENT':
            raise HTTPException(403, 'Windows agent required')
        file = check_hash(db, body.file_id, body.previous_hash)
        key = f'lineage:{endpoint.id}:{body.record_id}:{body.new_hash}'
        existing = db.scalar(select(Record).where(Record.dedup_key == key))
        if existing:
            return {**public(existing), 'duplicate': True}
        if body.new_hash == body.previous_hash:
            raise HTTPException(422, 'Content did not change')
        if any(body.new_hash in f.data['hashes'] and f.id != file.id for f in rows(db, 'file')):
            raise HTTPException(409, 'New content already belongs to another registered file')
        row = add(db, 'lineage', {**body.model_dump(mode='json'), 'device_id': endpoint.id, 'confidence': 'OBSERVED_WRITE_AND_STABLE_FILE_ID; NOT_HASH_ONLY_PROOF'}, dedup_key=key)
        file.data = {**file.data, 'hashes': list(dict.fromkeys(file.data['hashes'] + [body.new_hash]))}
        audit(db, endpoint.id, 'LINEAGE_RECORDED', row.id)
        db.commit()
        return public(row)

    @app.get('/api/lineage')
    def list_lineage(account=Depends(security_user), db=Depends(session)):
        return [public(r) for r in rows(db, 'lineage')]

    @app.post('/api/agent/diagnostics')
    def diagnostic(body: Diagnostic, endpoint=Depends(device), db=Depends(session)):
        key = 'diagnostic:' + endpoint.id + ':' + body.external_id
        existing = db.scalar(select(Record).where(Record.dedup_key == key))
        if existing:
            return public(existing)
        row = add(db, 'diagnostic', {**body.model_dump(mode='json'), 'device_id': endpoint.id, 'status': 'COLLECTION_FAILED'}, dedup_key=key)
        audit(db, endpoint.id, body.code, row.id)
        db.commit()
        return public(row)

    @app.get('/api/diagnostics')
    def diagnostics(account=Depends(security_user), db=Depends(session)):
        return [public(r) for r in rows(db, 'diagnostic')][:500]

    @app.get('/api/integrity')
    def integrity(account=Depends(admin), db=Depends(session)):
        records = db.scalars(select(Record)).all()
        invalid = [r.id for r in records if r.seal and not hmac.compare_digest(r.seal, record_signature(integrity_key, r))]
        unsigned = [r.id for r in records if not r.seal]
        return {'checked': len(records), 'invalid': invalid, 'legacy_unsigned': unsigned, 'ok': not invalid and not unsigned, 'limitation': 'Record MAC detects edits, not privileged deletion or full database rollback. External immutable backup required.'}

    @app.post('/api/integrations/movements')
    def movement(body: Movement, endpoint=Depends(device), db=Depends(session)):
        expected = ('WINDOWS_AGENT', 'APPROVED_COPY_TOOL') if body.channel == 'USB' else ('SMTP_GATEWAY', 'SMTP_AUDIT_LOG')
        if (endpoint.data['kind'], body.evidence_type) != expected:
            raise HTTPException(403, 'Connector is not authorized for this evidence type')
        ids = artifact_ids(db, body.file_id, body.distribution_id, body.sha256)
        for field in ['distribution_id', 'issuance_id']:
            if getattr(body, field) and getattr(body, field) != ids.get(field):
                raise HTTPException(422, 'Movement artifact identity mismatch')
        if body.channel == 'USB' and (not body.copy_observed or not body.usb_device_id or body.stage not in {None, 'FILE_COPIED_TO_USB'}):
            raise HTTPException(422, 'Completed USB copy and hardware identifier required')
        if body.channel == 'EMAIL' and body.stage and (body.stage == 'FILE_COPIED_TO_USB' or not body.message_id):
            raise HTTPException(422, 'Email stages require a gateway message ID')
        if body.recipient_device_id:
            recipient = db.get(Record, body.recipient_device_id)
            if not recipient or recipient.kind != 'device' or recipient.data['kind'] != 'WINDOWS_AGENT':
                raise HTTPException(422, 'Registered recipient device required')
        key = f'movement:{endpoint.id}:{body.external_id}'
        existing = db.scalar(select(Record).where(Record.dedup_key == key))
        if existing:
            return {**public(existing), 'duplicate': True}
        row = add(db, 'movement', {**body.model_dump(mode='json'), **ids, 'device_id': endpoint.id, 'received_at': now(), 'evidence_level': 'CORRELATED_TRANSFER', 'evidence_origin': 'AUTHENTICATED_CONNECTOR', 'evidence_note': 'Authenticated connector observed transfer; its relation to a later access remains inferred'}, dedup_key=key)
        audit(db, endpoint.id, 'MOVEMENT_RECORDED', row.id)
        db.commit()
        return public(row)

    @app.get('/api/events')
    def events(limit: int = 200, file_id: str | None = None, account=Depends(user), db=Depends(session)):
        result = [public(r) for r in rows(db, 'event') if not file_id or r.data['file_id'] == file_id][:max(1, min(limit, 1000))]
        if account.data['role'] == 'viewer':
            private = {'observed_public_ip', 'local_ip', 'windows_sid', 'volume_id', 'usb_device_id', 'user_agent', 'windows_user', 'pc_name', 'device_name', 'object_path', 'file_path', 'process', 'process_name', 'process_id', 'device_id', 'request_path'}
            result = [{k: v for k, v in r.items() if k not in private} for r in result]
        return result

    @app.get('/api/summary')
    def summary(account=Depends(user), db=Depends(session)):
        ev = rows(db, 'event')
        return {'issued_tokens': len(rows(db, 'token')), 'active_files': sum(r.data['active'] for r in rows(db, 'file')), 'today_events': sum(r.data['received_at'][:10] == now()[:10] for r in ev), 'external_events': sum(r.data['policy_verdict'] == 'EXTERNAL_SUSPECTED' for r in ev), 'total_events': len(ev), 'timezone': 'UTC'}

    @app.get('/api/analysis')
    def analysis(account=Depends(security_user), db=Depends(session)):
        return {'engine': 'LOCAL_RULES_V1', 'external_ai_used': False, 'events': [{'event_id': r.data['event_id'], 'analysis': r.data.get('analysis')} for r in rows(db, 'event')[:200]]}

    # 기존 진입 경로를 유지하되 인증된 중앙 저장소를 사용합니다.
    app.add_api_route('/api/logs', events, methods=['GET'])
    app.add_api_route('/api/logs', endpoint_event, methods=['POST'])
    app.add_api_route('/api/analyze', analysis, methods=['POST'])
    app.add_api_route('/health', health, methods=['GET'])

    @app.get('/api/routes')
    def routes(account=Depends(security_user), db=Depends(session)):
        # 같은 파일·시간대의 이동은 경로 후보입니다. 이메일·USB가 실제 전달 경로였다고 단정하지 않습니다.
        policy = db.get(Record, 'policy').data
        from .correlation import correlate
        movements = [public(r) for r in rows(db, 'movement')]
        observations = [public(r) for r in rows(db, 'endpoint_observation')]
        result = []
        for e in rows(db, 'event')[:500]:
            result.append({'event_id': e.data['event_id'], 'file_id': e.data['file_id'], 'file_name': e.data['file_name'], 'occurred_at': e.data['occurred_at'], **correlate(e.data, movements, observations, policy['correlation_hours'])})
        return result

    @app.get('/api/movements')
    def movements(account=Depends(security_user), db=Depends(session)):
        return [public(r) for r in rows(db, 'movement')][:500]

    @app.get('/api/audit')
    def audits(account=Depends(security_user), db=Depends(session)):
        return [public(r) for r in rows(db, 'audit')][:1000]

    @app.get('/api/policy')
    def policy(account=Depends(user), db=Depends(session)):
        if account.data['role'] == 'viewer':
            return {'retention_days': db.get(Record, 'policy').data['retention_days']}
        return {**db.get(Record, 'policy').data, 'trusted_proxies': trusted, 'public_base_url': base_url}

    @app.put('/api/policy')
    def policy_update(body: Policy, account=Depends(admin), db=Depends(session)):
        db.get(Record, 'policy').data = body.model_dump()
        audit(db, account.id, 'POLICY_UPDATED', 'policy', policy=body.model_dump())
        db.commit()
        return body

    @app.post('/api/retention/purge')
    def purge(account=Depends(admin), db=Depends(session)):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=db.get(Record, 'policy').data['retention_days'])).isoformat()
        count = 0
        for row in db.scalars(select(Record).where(Record.kind.in_(['event', 'movement', 'audit', 'session', 'diagnostic', 'lineage', 'notification', 'alert', 'investigation', 'endpoint_observation', 'distribution_download']), Record.created_at < cutoff)):
            db.delete(row)
            count += 1
        audit(db, account.id, 'RETENTION_PURGED', 'policy', deleted=count, cutoff=cutoff)
        db.commit()
        return {'deleted': count, 'cutoff': cutoff, 'original_files_preserved': True}

    @app.get('/api/stream')
    async def stream(request: Request, account=Depends(user)):
        # 실시간 스트림에는 갱신 번호만 보냅니다. 상세 개인정보는 권한 검사된 REST 조회로 가져옵니다.
        # No IPs in stream; authenticated clients refresh authorized REST views.
        session_id = 'session:' + digest(request.headers['authorization'][7:])
        async def generate():
            previous = None
            while not await request.is_disconnected():
                with Session() as db:
                    live = db.get(Record, session_id)
                    if not live or live.data['expires_at'] <= now():
                        return
                    latest = db.scalar(select(Record).where(Record.kind == 'audit').order_by(Record.created_at.desc()).limit(1))
                    revision = latest.id if latest else '0'
                if revision != previous:
                    yield 'event: refresh\ndata: ' + json.dumps({'revision': revision}) + '\n\n'
                    previous = revision
                else:
                    yield ': heartbeat\n\n'
                await asyncio.sleep(1)
        return StreamingResponse(generate(), media_type='text/event-stream', headers={'X-Accel-Buffering': 'no'})

    dist = ROOT / 'frontend' / 'dist'
    # 이전 버전에서 등록한 기밀문서의 토큰 누락을 보완합니다. 명시적으로 폐기한 토큰은 재활성화하지 않습니다.
    with Session() as db:
        owner = db.get(Record, 'admin')
        for file in rows(db, 'file'):
            if file.data['active'] and file.data['classification'] in {'CONFIDENTIAL', 'RESTRICTED'} and not file.data.get('token_provisioned'):
                if not any(t.data['file_id'] == file.id for t in rows(db, 'token')):
                    token(NewToken(file_id=file.id, approved_test_document=True), owner, db)
                else:
                    file.data = {**file.data, 'token_provisioned': True}
                    db.commit()
        # 이전 토큰을 재발급하거나 URL을 바꾸지 않고 다운로드용 메타데이터만 마이그레이션합니다.
        for old in rows(db, 'token'):
            if old.data.get('decoy_id'):
                continue
            source = get_file(db, old.data['file_id'])
            fmt = 'html' if old.data['mode']=='WEB_BEACON_HTML' else source.data['extension']
            mime = {'html':'text/html','txt':'text/plain; charset=utf-8','pdf':'application/pdf','docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document'}[fmt]
            d = add(db,'decoy',{'file_id':source.id,'token_id':old.id,'file_name':'tracked-'+source.data['name']+('.html' if fmt=='html' else ''),'document_format':fmt,'classification':source.data['classification'],'issued_by':'admin','tracking_status':'ACTIVE' if old.data['active'] else 'INACTIVE','sha256':old.data['artifact_sha256'],'media_type':mime})
            d.data={**d.data,'decoy_id':d.id}
            old.data={**old.data,'decoy_id':d.id}
            audit(db,'migration','DECOY_METADATA_MIGRATED',d.id,file_id=source.id)
            db.commit()
    if dist.exists():
        app.mount('/', StaticFiles(directory=dist, html=True), name='dashboard')
    return app
