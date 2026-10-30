"""Authenticated endpoint observations, separate from file read evidence."""
from datetime import datetime, timezone, timedelta
from typing import Literal
from pydantic import BaseModel, Field, field_validator
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from .db import Record, add, audit, now, public, rows
from .distributions import issuance_for_hash


class Observation(BaseModel):
    external_id: str = Field(min_length=1, max_length=200)
    event_type: Literal['USB_PRESENT', 'USB_CONNECTED', 'USB_DISCONNECTED', 'COPY_ATTEMPT', 'COPY_FAILED', 'FILE_WRITE_COMPLETED', 'FILE_WRITE_OBSERVED', 'FILE_RENAMED', 'FILE_MOVED', 'ZIP_EXTRACTED']
    occurred_at: datetime
    pc_name: str = Field(min_length=1, max_length=200)
    windows_user: str = Field(default='UNKNOWN', max_length=300)
    windows_sid: str = Field(default='UNKNOWN', max_length=200)
    file_id: str | None = None
    sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')
    distribution_id: str | None = None
    issuance_id: str | None = None
    object_path: str = Field(default='', max_length=2000)
    previous_path: str | None = Field(default=None, max_length=2000)
    process: str | None = Field(default=None, max_length=1000)
    process_id: str | None = Field(default=None, max_length=30)
    storage_type: Literal['LOCAL', 'USB', 'REMOVABLE', 'NETWORK', 'UNKNOWN'] = 'UNKNOWN'
    usb_device_id: str | None = Field(default=None, max_length=300)
    volume_id: str | None = Field(default=None, max_length=200)
    file_identity: str | None = Field(default=None, max_length=200)
    record_id: int | None = Field(default=None, ge=1)
    observation_method: Literal['VOLUME_SNAPSHOT_DIFF', 'STABLE_FILE_ID_SNAPSHOT', 'WINDOWS_SECURITY_4663', 'APPROVED_COPY_TOOL', 'APPROVED_EXTRACT_TOOL']

    @field_validator('occurred_at')
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None or value > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError('Valid timezone-aware timestamp required')
        return value.astimezone(timezone.utc)


def artifact_ids(db, file_id, distribution_id, sha):
    if file_id:
        file = db.get(Record, file_id)
        if not file or file.kind != 'file' or not file.data['active'] or sha not in file.data['hashes'] or file.data['classification'] not in {'CONFIDENTIAL', 'RESTRICTED'}:
            raise HTTPException(422, 'Active tracked file hash required')
        return issuance_for_hash(db, file_id, sha)
    if distribution_id:
        row = db.get(Record, distribution_id)
        if not row or row.kind != 'distribution' or row.data['sha256'] != sha:
            raise HTTPException(422, 'Registered ZIP hash required')
        return {'distribution_id': row.id}
    raise HTTPException(422, 'Registered file or distribution required')


def install_telemetry(app, *, session, device, security_user, observed_ip):
    @app.post('/api/agent/observations')
    def receive(body: Observation, request: Request, endpoint=Depends(device), db=Depends(session)):
        if endpoint.data['kind'] != 'WINDOWS_AGENT':
            raise HTTPException(403, 'Windows device required')
        expected = {'USB_PRESENT': 'VOLUME_SNAPSHOT_DIFF', 'USB_CONNECTED': 'VOLUME_SNAPSHOT_DIFF', 'USB_DISCONNECTED': 'VOLUME_SNAPSHOT_DIFF', 'FILE_RENAMED': 'STABLE_FILE_ID_SNAPSHOT', 'FILE_MOVED': 'STABLE_FILE_ID_SNAPSHOT', 'FILE_WRITE_OBSERVED': 'WINDOWS_SECURITY_4663', 'COPY_ATTEMPT': 'APPROVED_COPY_TOOL', 'COPY_FAILED': 'APPROVED_COPY_TOOL', 'FILE_WRITE_COMPLETED': 'APPROVED_COPY_TOOL', 'ZIP_EXTRACTED': 'APPROVED_EXTRACT_TOOL'}
        if body.observation_method != expected[body.event_type]:
            raise HTTPException(422, 'Evidence method does not match event')
        if body.event_type.startswith('USB_'):
            if body.storage_type != 'USB' or not body.usb_device_id:
                raise HTTPException(422, 'USB bus and stable hardware identifier required')
            ids = {}
            if body.file_id or body.distribution_id or body.issuance_id:
                raise HTTPException(422, 'Device presence is not file movement evidence')
        else:
            ids = artifact_ids(db, body.file_id, body.distribution_id, body.sha256)
            if body.event_type in {'FILE_RENAMED', 'FILE_MOVED'} and (not body.previous_path or not body.file_identity):
                raise HTTPException(422, 'Stable identity and previous path required')
            if body.event_type == 'FILE_WRITE_OBSERVED' and not body.record_id:
                raise HTTPException(422, 'Windows audit record required')
            if body.event_type == 'ZIP_EXTRACTED' and (body.file_id or not body.distribution_id):
                raise HTTPException(422, 'ZIP distribution required')
        for key in ['distribution_id', 'issuance_id']:
            if getattr(body, key) and getattr(body, key) != ids.get(key):
                raise HTTPException(422, 'Artifact identity mismatch')
        dedup = 'observation:' + endpoint.id + ':' + body.external_id
        old = db.scalar(select(Record).where(Record.dedup_key == dedup))
        if old: return {**public(old), 'duplicate': True}
        data = {**body.model_dump(mode='json'), **ids, 'device_id': endpoint.id, 'device_name': body.pc_name, 'received_at': now(), 'observed_public_ip': observed_ip(request), 'evidence_origin': 'AUTHENTICATED_ENDPOINT_OBSERVATION', 'evidence_level': 'CORRELATED' if body.event_type in {'FILE_MOVED', 'FILE_RENAMED'} else 'CONFIRMED', 'human_read_confirmed': False,
                'limitation': 'Snapshot times bound observations; a write audit is not proof of copy completion. Device reports require trust in the enrolled endpoint.'}
        row = add(db, 'endpoint_observation', data, dedup_key=dedup)
        audit(db, endpoint.id, body.event_type, row.id, distribution_id=ids.get('distribution_id'), file_id=body.file_id)
        try: db.commit()
        except IntegrityError:
            db.rollback()
            old = db.scalar(select(Record).where(Record.dedup_key == dedup))
            if old: return {**public(old), 'duplicate': True}
            raise
        return {**public(row), 'duplicate': False}

    @app.get('/api/observations')
    def observations(account=Depends(security_user), db=Depends(session)):
        return [public(r) for r in rows(db, 'endpoint_observation')][:1000]
