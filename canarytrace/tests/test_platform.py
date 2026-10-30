"""Synthetic/isolated security tests. These are not physical USB/mail/PC-B tests."""
import hashlib
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
import pytest
from docx import Document
from docx.oxml.ns import qn
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from fastapi.testclient import TestClient
from backend.app import create_app
from backend.correlation import correlate
from backend.db import now
from backend.security import process_category
from scripts.ccc_distribution import synthetic_documents
from conftest import signed, event


def distribution(s):
    raw = synthetic_documents()['ccc-test.docx']
    r = s['client'].post('/api/files', headers=s['headers'], files={'file': ('approved.docx', raw)}, data={'classification': 'CONFIDENTIAL'})
    r.raise_for_status()
    d = s['client'].post('/api/distributions', headers=s['headers'], json={'file_ids': [r.json()['id']], 'approved_test_documents': True, 'docx_remote_image': True})
    d.raise_for_status(); return d.json()


def test_docx_external_image_and_beacon(system):
    s = system; c = s['client']; d = distribution(s); item = d['files'][0]
    raw = c.get('/api/distributions/' + d['id'] + '/download', headers=s['headers']).content
    with zipfile.ZipFile(io.BytesIO(raw)) as z: doc = Document(io.BytesIO(z.read(item['archive_path'])))
    blips = doc.element.xpath('.//a:blip'); assert len(blips) == 1
    assert blips[0].get(qn('r:embed')) is None
    relationship = doc.part.rels[blips[0].get(qn('r:link'))]
    assert relationship.is_external and relationship.reltype == RT.IMAGE
    assert 'APPROVED CANARYTRACE REMOTE IMAGE' in '\n'.join(p.text for p in doc.paragraphs)
    assert c.get('/api/events', headers=s['headers']).json() == []  # Document construction causes no network request.
    r = c.get(urlsplit(relationship.target_ref).path)
    assert r.status_code == 200 and r.headers['content-type'] == 'image/png' and r.content.startswith(b'\x89PNG')
    e = c.get('/api/events', headers=s['headers']).json()[0]
    assert e['issuance_id'] == item['issuance_id'] and e['decoy_id'] == item['decoy_id']
    assert e['document_mode'] == 'DOCX_REMOTE_IMAGE' and e['request_path'].startswith('/b/')
    assert not e['human_read_confirmed'] and not e['scanner_suspected'] and 'pc_name' not in e


def observation(**kwargs):
    return {'external_id': 'observation-1', 'event_type': 'USB_CONNECTED', 'occurred_at': now(), 'pc_name': 'TEST-PC-B', 'observation_method': 'VOLUME_SNAPSHOT_DIFF', 'storage_type': 'USB', 'usb_device_id': 'SYNTHETIC-USB-ID', **kwargs}


def test_observation_auth_dedup_and_privacy(system):
    s = system; c = s['client']; path = '/api/agent/observations'; body = observation()
    assert c.post(path, json=body).status_code == 401
    assert signed(c, path, body, s['device']).status_code == 200
    assert signed(c, path, body, s['device']).json()['duplicate']
    assert len(c.get('/api/observations', headers=s['headers']).json()) == 1
    assert signed(c, path, observation(external_id='forged', storage_type='LOCAL'), s['device']).status_code == 422
    assert signed(c, path, observation(external_id='wrong-kind', observation_method='APPROVED_COPY_TOOL'), s['device']).status_code == 422


def test_approved_zip_extraction_observation(system):
    s = system; c = s['client']; d = distribution(s)
    body = observation(event_type='ZIP_EXTRACTED', observation_method='APPROVED_EXTRACT_TOOL', storage_type='LOCAL', usb_device_id=None, distribution_id=d['id'], sha256=d['sha256'])
    assert signed(c, '/api/agent/observations', body, s['device']).status_code == 200
    response = c.get('/api/distributions/' + d['id'], headers=s['headers']).json()
    assert response['extraction_status'] == 'OBSERVED_APPROVED_EXTRACTION'
    assert next(n for n in response['graph'] if n['id'] == 'extract')['evidence'] == 'CONFIRMED'
    body.update(external_id='tampered', sha256='0'*64)
    assert signed(c, '/api/agent/observations', body, s['device']).status_code == 422


@pytest.mark.parametrize('channel', ['USB', 'EMAIL'])
def test_rich_movement_correlation(system, channel):
    s = system; c = s['client']; d = distribution(s); item = d['files'][0]
    connector = s['device'] if channel == 'USB' else c.post('/api/devices', headers=s['headers'], json={'name': 'TEST-GATEWAY', 'kind': 'SMTP_GATEWAY'}).json()
    body = {'file_id': item['file_id'], 'sha256': item['file_hash'], 'distribution_id': d['id'], 'issuance_id': item['issuance_id'], 'external_id': 'test-transfer', 'occurred_at': now(), 'channel': channel, 'source': 'TEST-SOURCE', 'destination': 'TEST-RECIPIENT', 'evidence_reference': 'ISOLATED_TEST_FIXTURE', 'evidence_type': 'APPROVED_COPY_TOOL' if channel == 'USB' else 'SMTP_AUDIT_LOG', 'copy_observed': channel == 'USB', 'usb_device_id': 'TEST-USB' if channel == 'USB' else None, 'message_id': 'TEST-MESSAGE' if channel == 'EMAIL' else None, 'stage': 'FILE_COPIED_TO_USB' if channel == 'USB' else 'EMAIL_ATTACHMENT_SENT', 'recipient_device_id': s['device']['id']}
    assert signed(c, '/api/integrations/movements', body, connector).status_code == 200
    if channel == 'EMAIL':
        assert signed(c, '/api/integrations/movements', {**body, 'external_id': 'delivery', 'stage': 'EMAIL_DELIVERED'}, connector).status_code == 200
    payload = event(s, file_id=item['file_id'], sha256=item['file_hash'], distribution_id=d['id'], issuance_id=item['issuance_id'], usb_device_id='TEST-USB' if channel == 'USB' else None)
    assert signed(c, '/api/agent/events', payload, s['device']).status_code == 200
    route = c.get('/api/routes', headers=s['headers']).json()[0]
    assert route['relation_evidence'] == 'CORRELATED' and route['route'] == 'UNKNOWN'
    assert all(x['same_issuance'] for x in route['candidates'])
    assert next(x for x in route['evidence_graph'] if x['step'] == 'FILE_EXTRACTED')['evidence'] == 'UNKNOWN'
    if channel == 'EMAIL':
        assert next(x for x in route['evidence_graph'] if x['step'] == 'EMAIL_DELIVERED')['evidence'] == 'CONFIRMED'


def test_hash_only_never_confirms_route():
    instant = now()
    e = {'file_id': 'f', 'sha256': 'a', 'occurred_at': instant, 'source_type': 'WINDOWS_SECURITY_4663'}
    m = {'id': 'm', 'file_id': 'f', 'sha256': 'a', 'occurred_at': instant, 'channel': 'USB'}
    r = correlate(e, [m], [])
    assert r['route'] == 'UNKNOWN' and r['relation_evidence'] == 'INFERRED'
    assert not r['candidates'][0]['route_confirmed']
    assert not correlate({**e, 'sha256': 'b'}, [m], [])['candidates']
    assert not correlate({**e, 'issuance_id': 'one', 'distribution_id': 'dist'}, [{**m, 'issuance_id': 'two', 'distribution_id': 'dist'}], [])['candidates']


@pytest.mark.parametrize('process,expected', [('winword.exe', 'USER_APPLICATION_CANDIDATE'), ('explorer.exe', 'EXPLORER_OR_PREVIEW'), ('msmpeng.exe', 'ANTIVIRUS_SCAN'), ('SearchIndexer.exe', 'SEARCH_INDEXING'), ('unknown.exe', 'OTHER_FILE_READ')])
def test_process_distinctions(process, expected): assert process_category(process) == expected










def test_ccc_selection_fingerprint_and_preservation(system, tmp_path, monkeypatch):
    source = tmp_path / 'ccc'; source.mkdir(); original = source / 'test.txt'; original.write_text('Approved actual test file')
    import scripts.ccc_distribution as discovery
    monkeypatch.setattr(discovery, 'desktop_context', lambda: {'user': 'TEST', 'desktop': str(tmp_path), 'candidates': [str(source)]})
    app = create_app(system['cfg'])
    try:
        with TestClient(app, base_url='https://testserver') as c:
            assert c.get('/api/sources/ccc').status_code == 401
            candidate = c.get('/api/sources/ccc', headers=system['headers']).json()['sources'][0]
            body = {'source_id': candidate['source_id'], 'fingerprint': candidate['fingerprint_id'], 'approved_test_documents': True}
            assert c.post('/api/sources/ccc/import', headers=system['headers'], json={**body, 'source_id': 'arbitrary-path'}).status_code == 404
            r = c.post('/api/sources/ccc/import', headers=system['headers'], json=body)
            assert r.status_code == 200 and r.json()['source_preserved']
            assert original.read_text() == 'Approved actual test file'
            original.write_text('Changed externally')
            assert c.post('/api/sources/ccc/import', headers=system['headers'], json=body).status_code == 409
    finally: app.state.engine.dispose()


def test_ccc_rejects_unsafe_archive_without_registration(system, tmp_path, monkeypatch):
    source = tmp_path / 'ccc.zip'
    with zipfile.ZipFile(source, 'w') as z: z.writestr('../escape.txt', 'test')
    import scripts.ccc_distribution as discovery
    monkeypatch.setattr(discovery, 'desktop_context', lambda: {'candidates': [str(source)]})
    app = create_app(system['cfg'])
    try:
        with TestClient(app, base_url='https://testserver') as c:
            before = c.get('/api/files', headers=system['headers']).json()
            candidate = c.get('/api/sources/ccc', headers=system['headers']).json()['sources'][0]
            response = c.post('/api/sources/ccc/import', headers=system['headers'], json={'source_id': candidate['source_id'], 'fingerprint': candidate['fingerprint_id'], 'approved_test_documents': True})
            assert response.status_code == 422
            assert c.get('/api/files', headers=system['headers']).json() == before
            assert not (tmp_path / 'escape.txt').exists()
    finally: app.state.engine.dispose()
