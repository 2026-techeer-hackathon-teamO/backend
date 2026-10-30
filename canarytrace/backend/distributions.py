"""Immutable ZIP issuances built from approved registered documents."""
import hashlib
import hmac
import io
import json
import secrets
import uuid
import zipfile
from typing import Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.services.decoy import render_decoy
from .archives import MAX_TOTAL, safe_member, zip_entries
from .db import Record, add, audit, now, public, rows
from .security import digest, record_signature


class DistributionRequest(BaseModel):
    file_ids: list[str] = Field(min_length=1, max_length=100)
    approved_test_documents: Literal[True]
    name: str = Field(default='ccc', min_length=1, max_length=80, pattern=r'^[\w -]+$')
    source_label: str = Field(default='ccc', min_length=1, max_length=200)
    source_kind: Literal['APPROVED_SOURCE', 'SYNTHETIC_TEST_DATA'] = 'APPROVED_SOURCE'
    recipient_ids: list[str] = Field(default_factory=list, max_length=100)
    include_beacon_html: bool = False
    docx_remote_image: bool = False


def issuance_for_hash(db, file_id, sha):
    matches = [r for r in rows(db, 'issuance') if r.data['file_id'] == file_id and r.data['file_hash'] == sha]
    if len(matches) == 1:
        return {k: matches[0].data[k] for k in ['distribution_id', 'issuance_id', 'file_id', 'decoy_id', 'token_id']}
    return {}


def install_distribution_routes(app, *, session, admin, user, security_user, blob_dir, integrity_key, base_url, limiter, observed_ip):
    api = APIRouter(prefix='/api', tags=['distributions'])
    storage = blob_dir.parent / 'distributions'
    storage.mkdir(exist_ok=True)

    def sealed(row):
        return row and row.seal and hmac.compare_digest(row.seal, record_signature(integrity_key, row))

    def get_distribution(db, identifier):
        row = db.get(Record, identifier)
        if not row or row.kind != 'distribution':
            raise HTTPException(404, 'Distribution not found')
        if not sealed(row):
            raise HTTPException(409, 'Distribution metadata integrity failure')
        return row

    def describe(db, row):
        related = [public(e) for e in rows(db, 'event') if e.data.get('distribution_id') == row.id]
        downloads = [public(d) for d in rows(db, 'distribution_download') if d.data['distribution_id'] == row.id]
        alerts = [public(a) for a in rows(db, 'alert') if a.data.get('distribution_id') == row.id]
        file_access = [e for e in related if e['source_type'] == 'WINDOWS_SECURITY_4663']
        beacon = [e for e in related if e['source_type'] in {'WEB_BEACON', 'TOKEN_URL'}]
        issued = [db.get(Record, item['issuance_id']) for item in row.data['files']]
        from .correlation import correlate
        observations = [public(o) for o in rows(db, 'endpoint_observation')]
        extracts = [o for o in observations if o.get('distribution_id') == row.id and o['event_type'] == 'ZIP_EXTRACTED']
        movements = [public(m) for m in rows(db, 'movement')]
        return {**public(row), 'files': [public(item) for item in issued if item], 'events': related, 'downloads': downloads, 'alerts': alerts,
                'observations': [o for o in observations if o.get('distribution_id') == row.id],
                'routes': [{'event_id': e['event_id'], **correlate(e, movements, observations, db.get(Record, 'policy').data['correlation_hours'])} for e in related],
                'access_status': 'FILE_ACCESS_OBSERVED' if file_access else ('HTTP_REQUEST_OBSERVED' if beacon else 'UNKNOWN'),
                'human_read_status': 'UNKNOWN', 'extraction_status': 'OBSERVED_APPROVED_EXTRACTION' if extracts else 'UNKNOWN',
                'graph': [
                    {'id': 'source', 'label': row.data['source_label'], 'evidence': 'CONFIRMED', 'note': row.data['source_kind']},
                    {'id': 'zip', 'label': 'ZIP 생성', 'evidence': 'CONFIRMED'},
                    {'id': 'download', 'label': 'ZIP 다운로드 응답', 'evidence': 'CONFIRMED' if downloads else 'UNKNOWN', 'note': 'Response issued; remote disk save is not established'},
                    {'id': 'extract', 'label': '관리 PC 압축 해제', 'evidence': 'CONFIRMED' if extracts else 'UNKNOWN', 'note': ', '.join(o['pc_name'] for o in extracts)},
                    {'id': 'access', 'label': '문서 파일 접근', 'evidence': 'CONFIRMED' if file_access else 'UNKNOWN'},
                    {'id': 'event', 'label': '에이전트 / HTTP 요청 수신', 'evidence': 'CONFIRMED' if related else 'UNKNOWN'},
                    {'id': 'network', 'label': '내부/외부 CIDR 판정', 'evidence': 'INFERRED' if related else 'UNKNOWN', 'note': 'VPN/NAT/proxy may affect classification; IP does not identify a person'},
                    {'id': 'alert', 'label': '관리자 경고 기록', 'evidence': 'CONFIRMED' if alerts else 'UNKNOWN'}],
                'relation_evidence': 'CORRELATED' if related else 'UNKNOWN',
                'warning': '동일 사본이 재전달될 수 있습니다. 수신자와 실제 열람자의 동일성 및 사람의 열람은 미확정입니다.'}

    @api.get('/distributions')
    def list_distributions(account=Depends(security_user), db=Depends(session)):
        return [describe(db, r) for r in rows(db, 'distribution')]

    @api.get('/distributions/{distribution_id}')
    def detail(distribution_id: str, account=Depends(security_user), db=Depends(session)):
        return describe(db, get_distribution(db, distribution_id))

    @api.post('/distributions')
    def create(body: DistributionRequest, account=Depends(admin), db=Depends(session)):
        limiter.check('distribution-create:' + account.id, 20)
        if len(set(body.file_ids)) != len(body.file_ids):
            raise HTTPException(422, 'Duplicate file IDs')
        for identifier in body.recipient_ids:
            recipient = db.get(Record, identifier)
            if not recipient or recipient.kind != 'user':
                raise HTTPException(422, 'Unknown recipient account')
        # Validate all sources before writing anything. Inputs are IDs, never server paths.
        sources, total = [], 0
        for identifier in body.file_ids:
            file = db.get(Record, identifier)
            if not file or file.kind != 'file':
                raise HTTPException(404, 'Source file not found')
            if not sealed(file) or not file.data['active'] or file.data['classification'] not in {'CONFIDENTIAL', 'RESTRICTED'}:
                raise HTTPException(409, 'Active, intact tracked source required')
            try:
                uuid.UUID(file.id)
                raw = (blob_dir / file.id).read_bytes()
            except (OSError, ValueError):
                raise HTTPException(409, 'Source unavailable')
            if hashlib.sha256(raw).hexdigest() != file.data['sha256']:
                raise HTTPException(409, 'Source hash mismatch')
            total += len(raw)
            if total > MAX_TOTAL:
                raise HTTPException(413, 'Distribution size limit exceeded')
            sources.append((file, raw))
        distribution_id, created = str(uuid.uuid4()), now()
        entries, members, pending = {}, [], []
        for file, raw in sources:
            modes = ['DOCX_REMOTE_IMAGE' if body.docx_remote_image and file.data['extension'] == 'docx' else 'EXPLICIT_LINK_ONLY'] + (['WEB_BEACON_HTML'] if body.include_beacon_html else [])
            for mode in modes:
                issuance_id, token_id, decoy_id = (str(uuid.uuid4()) for _ in range(3))
                secret = secrets.token_urlsafe(32)
                url = base_url + ('/b/' if mode in {'WEB_BEACON_HTML', 'DOCX_REMOTE_IMAGE'} else '/t/') + secret
                content, fmt, mime = render_decoy(raw, file.data['name'], url, file.id, mode)
                sha = hashlib.sha256(content).hexdigest()
                name = safe_member('documents/' + issuance_id + '/' + file.data['name'] + ('.html' if fmt == 'html' else ''))
                source_decoy = next((d.id for d in rows(db, 'decoy') if d.data['file_id'] == file.id and not d.data.get('distribution_id')), None)
                item = {'distribution_id': distribution_id, 'issuance_id': issuance_id, 'decoy_id': decoy_id, 'source_decoy_id': source_decoy, 'file_id': file.id, 'token_id': token_id, 'file_hash': sha, 'source_hash': file.data['sha256'], 'file_name': file.data['name'], 'archive_path': name, 'classification': file.data['classification'], 'document_format': fmt, 'mode': mode, 'size': len(content), 'created_at': created, 'downloaded_at': None, 'status': 'CREATED'}
                entries[name] = content
                members.append(item)
                pending.append((file, item, content, url, secret, mime))
        manifest = {'schema_version': 1, 'distribution_id': distribution_id, 'created_at': created, 'source_label': body.source_label, 'source_kind': body.source_kind, 'files': members,
                    'notice': 'Approved security test. Optional DOCX remote image and HTML request an image only if permitted by the viewer. Other documents use explicit links. No agent/no request: UNKNOWN. Reforwarding does not identify a reader.'}
        entries['manifest.json'] = json.dumps(manifest, ensure_ascii=False, indent=2).encode()
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, content in entries.items():
                archive.writestr(name, content)
        zipped = output.getvalue()
        try:
            if zip_entries(zipped) != entries:
                raise ValueError('ZIP verification failed')
        except ValueError as exc:
            raise HTTPException(413, str(exc))
        written = []
        try:
            for file, item, content, url, secret, mime in pending:
                path = blob_dir / item['token_id']
                with path.open('xb') as stream:
                    stream.write(content)
                written.append(path)
                token = add(db, 'token', {**item, 'active': True, 'url': url, 'artifact_sha256': item['file_hash'], 'approved_test_document': True, 'approved_by': account.id}, id=item['token_id'], dedup_key='token:' + digest(secret))
                add(db, 'decoy', {**item, 'tracking_status': 'ACTIVE', 'sha256': item['file_hash'], 'media_type': mime, 'issued_by': account.id}, id=item['decoy_id'])
                add(db, 'issuance', item, id=item['issuance_id'])
                file.data = {**file.data, 'hashes': list(dict.fromkeys(file.data['hashes'] + [item['file_hash']]))}
                add(db, 'lineage', {'file_id': file.id, 'distribution_id': distribution_id, 'issuance_id': item['issuance_id'], 'previous_hash': file.data['sha256'], 'new_hash': item['file_hash'], 'evidence_type': 'SERVER_GENERATED_APPROVED_TOKEN_COPY', 'occurred_at': created, 'token_id': token.id})
            path = storage / (distribution_id + '.zip')
            with path.open('xb') as stream:
                stream.write(zipped)
            written.append(path)
            row = add(db, 'distribution', {**manifest, 'filename': body.name + '-canary-distribution.zip', 'sha256': hashlib.sha256(zipped).hexdigest(), 'size': len(zipped), 'downloaded_at': None, 'status': 'CREATED', 'created_by': account.id, 'recipient_ids': body.recipient_ids}, id=distribution_id)
            audit(db, account.id, 'DISTRIBUTION_CREATED', distribution_id, distribution_id=distribution_id, source_kind=body.source_kind)
            db.commit()
        except Exception:
            db.rollback()
            for path in written:
                path.unlink(missing_ok=True)
            raise
        return describe(db, row)

    @api.get('/distributions/{distribution_id}/download')
    def download(distribution_id: str, request: Request, account=Depends(user), db=Depends(session)):
        row = get_distribution(db, distribution_id)
        if account.data['role'] != 'admin' and account.id not in row.data['recipient_ids']:
            audit(db, account.id, 'DISTRIBUTION_DOWNLOAD_DENIED', row.id, distribution_id=row.id)
            db.commit()
            raise HTTPException(403, 'Recipient grant required')
        limiter.check('distribution-download:' + account.id, 30)
        for item in row.data['files']:
            source, token = db.get(Record, item['file_id']), db.get(Record, item['token_id'])
            if not sealed(source) or not sealed(token) or not source.data['active'] or not token.data['active']:
                raise HTTPException(409, 'Distribution contains inactive or invalid documents')
        try:
            uuid.UUID(row.id)
            raw = (storage / (row.id + '.zip')).read_bytes()
            if hashlib.sha256(raw).hexdigest() != row.data['sha256']:
                raise ValueError('Hash mismatch')
        except (OSError, ValueError):
            audit(db, account.id, 'DISTRIBUTION_DOWNLOAD_FAILED', row.id, distribution_id=row.id)
            db.commit()
            raise HTTPException(409, 'ZIP unavailable or integrity failure')
        at = now()
        row.data = {**row.data, 'downloaded_at': at, 'status': 'DOWNLOAD_RESPONSE_ISSUED'}
        for item in row.data['files']:
            issuance = db.get(Record, item['issuance_id'])
            issuance.data = {**issuance.data, 'downloaded_at': at, 'status': 'DOWNLOAD_RESPONSE_ISSUED'}
        add(db, 'distribution_download', {'distribution_id': row.id, 'user_id': account.id, 'downloaded_at': at, 'observed_ip': observed_ip(request), 'sha256': row.data['sha256'], 'evidence': 'CONFIRMED_RESPONSE_ISSUED', 'remote_save_confirmed': False})
        audit(db, account.id, 'DISTRIBUTION_DOWNLOADED', row.id, distribution_id=row.id)
        db.commit()
        return Response(raw, media_type='application/zip', headers={'Content-Disposition': "attachment; filename*=UTF-8''" + quote(row.data['filename']), 'Cache-Control': 'no-store'})

    app.include_router(api)
