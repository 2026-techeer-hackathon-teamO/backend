"""Synthetic isolated tests; never claim these are physical remote-PC observations."""
import hashlib
import io
import json
import stat
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient
from docx import Document
from pypdf import PdfReader
from backend.app import create_app
from backend.archives import safe_member, zip_entries, extract_verified, source_files
from backend.db import Record
from scripts.ccc_distribution import inspect_source, synthetic_documents, file_info
from conftest import signed, event


def create(s, **extra):
    response = s['client'].post('/api/distributions', headers=s['headers'], json={'file_ids': [s['file']['id']], 'approved_test_documents': True, **extra})
    assert response.status_code == 200, response.text
    return response.json()


def test_unique_distribution_hashes_and_original_preservation(system, tmp_path):
    s = system
    first, second = create(s), create(s)
    a, b = first['files'][0], second['files'][0]
    for key in ['distribution_id', 'issuance_id', 'token_id', 'decoy_id', 'file_hash']:
        assert a[key] != b[key]
    assert a['file_id'] == b['file_id']
    raw = s['client'].get('/api/distributions/' + first['id'] + '/download', headers=s['headers']).content
    assert hashlib.sha256(raw).hexdigest() == first['sha256']
    entries = extract_verified(raw, tmp_path / 'extracted')
    assert set(entries) == {'manifest.json', a['archive_path']}
    assert hashlib.sha256(entries[a['archive_path']]).hexdigest() == a['file_hash']
    assert (tmp_path / 'extracted' / a['archive_path']).read_bytes() == entries[a['archive_path']]
    assert (s['cfg']['runtime'] / 'files' / s['file']['id']).read_bytes() == s['content']
    detail = s['client'].get('/api/distributions/' + first['id'], headers=s['headers']).json()
    assert detail['files'][0]['downloaded_at'] and detail['files'][0]['status'] == 'DOWNLOAD_RESPONSE_ISSUED'
    assert detail['files'][0]['source_decoy_id']
    assert first['access_status'] == 'UNKNOWN'
    assert next(n for n in first['graph'] if n['id'] == 'extract')['evidence'] == 'UNKNOWN'


def test_formats_and_beacon_linkage(system):
    s = system; c = s['client']; ids = []
    for name, raw in synthetic_documents().items():
        r = c.post('/api/files', headers=s['headers'], files={'file': (name, raw)}, data={'classification': 'CONFIDENTIAL'})
        r.raise_for_status(); ids.append(r.json()['id'])
    d = create(s, file_ids=ids, include_beacon_html=True, source_kind='SYNTHETIC_TEST_DATA')
    raw = c.get('/api/distributions/' + d['id'] + '/download', headers=s['headers']).content
    entries = zip_entries(raw)
    tokens = {t['id']: t for t in c.get('/api/tokens', headers=s['headers']).json()}
    for item in d['files']:
        data = entries[item['archive_path']]; url = tokens[item['token_id']]['url']
        assert hashlib.sha256(data).hexdigest() == item['file_hash']
        if item['document_format'] == 'docx':
            assert 'CCC approved' in Document(io.BytesIO(data)).paragraphs[0].text
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                assert url.encode() in z.read('word/_rels/document.xml.rels')
                assert not any('vbaproject' in n.lower() for n in z.namelist())
        elif item['document_format'] == 'pdf':
            doc = PdfReader(io.BytesIO(data)); assert len(doc.pages) == 2
            assert any(a.get_object().get('/A', {}).get('/URI') == url for a in doc.pages[-1]['/Annots'])
        elif item['document_format'] == 'txt':
            assert url.encode() in data and b'Opening this TXT alone sends no network request' in data
        else:
            assert b'<img' in data and url.encode() in data
        assert c.get(urlparse(url).path).status_code == 200
    detail = c.get('/api/distributions/' + d['id'], headers=s['headers']).json()
    assert len(detail['events']) == 6
    assert {e['issuance_id'] for e in detail['events']} == {i['issuance_id'] for i in d['files']}
    assert all(not e.get('pc_name') and not e['human_read_confirmed'] for e in detail['events'])


def test_download_auth_recipient_scope_and_integrity(system):
    s = system; c = s['client']
    recipient = c.post('/api/users', headers=s['headers'], json={'username': 'receiver', 'password': 'Receiver-test-password', 'role': 'recipient'}).json()
    d = create(s, recipient_ids=[recipient['id']]); path = '/api/distributions/' + d['id'] + '/download'
    assert c.get(path).status_code == 401
    h = {'Authorization': 'Bearer ' + c.post('/api/login', json={'username': 'receiver', 'password': 'Receiver-test-password'}).json()['access_token']}
    assert c.get(path, headers=h).status_code == 200
    assert c.get('/api/files/' + s['file']['id'] + '/original', headers=h).status_code == 403
    assert c.get('/api/distributions', headers=h).status_code == 403
    other = create(s)
    assert c.get('/api/distributions/' + other['id'] + '/download', headers=h).status_code == 403
    assert c.get('/api/distributions/missing/download', headers=s['headers']).status_code == 404
    zip_path = s['cfg']['runtime'] / 'distributions' / (d['id'] + '.zip')
    zip_path.write_bytes(b'tampered')
    assert c.get(path, headers=s['headers']).status_code == 409
    assert any(a['action'] == 'DISTRIBUTION_DOWNLOAD_FAILED' for a in c.get('/api/audit', headers=s['headers']).json())


def test_agent_hash_id_binding_and_restart(system):
    s = system; c = s['client']; d = create(s); item = d['files'][0]
    payload = event(s, sha256=item['file_hash'], distribution_id=d['id'], issuance_id=item['issuance_id'])
    r = signed(c, '/api/agent/events', payload, s['device']); assert r.status_code == 200
    invalid = signed(c, '/api/agent/events', {**payload, 'issuance_id': 'forged', 'record_id': 999}, s['device'])
    assert invalid.status_code == 422
    token = next(t for t in c.get('/api/tokens', headers=s['headers']).json() if t['id'] == item['token_id'])
    c.get(urlparse(token['url']).path)
    detail = c.get('/api/distributions/' + d['id'], headers=s['headers']).json()
    assert len(detail['events']) == 2
    assert {e['issuance_id'] for e in detail['events']} == {item['issuance_id']}
    assert detail['access_status'] == 'FILE_ACCESS_OBSERVED' and detail['extraction_status'] == 'UNKNOWN'
    manifest = c.get('/api/agent/manifest', headers={'X-Device-Key': s['device']['device_key']}).json()
    assert any(i['issuance_id'] == item['issuance_id'] for i in manifest['issuances'])
    restarted = create_app(s['cfg'])
    try:
        with TestClient(restarted, base_url='https://testserver') as client:
            assert client.get('/api/distributions/' + d['id'], headers=s['headers']).json()['events'] == detail['events']
            assert client.get('/api/integrity', headers=s['headers']).json()['ok']
    finally:
        restarted.state.engine.dispose()


@pytest.mark.parametrize('scanner,internal,expected,alert', [(False, True, 'INTERNAL_ACCESS', False), (False, False, 'EXTERNAL_ACCESS', True), (True, False, 'SUSPECTED_SCANNER', False)])
def test_distribution_network_alerts(system, scanner, internal, expected, alert):
    s = system; c = s['client']; d = create(s)
    c.put('/api/policy', headers=s['headers'], json={'allowed_networks': ['127.0.0.0/8'] if internal else ['10.0.0.0/8']}).raise_for_status()
    token = next(t for t in c.get('/api/tokens', headers=s['headers']).json() if t['id'] == d['files'][0]['token_id'])
    c.get(urlparse(token['url']).path, headers={'User-Agent': 'Proofpoint scanner' if scanner else 'Test Browser'})
    detail = c.get('/api/distributions/' + d['id'], headers=s['headers']).json()
    assert detail['events'][0]['network_verdict'] == expected
    assert bool(detail['alerts']) == alert


@pytest.mark.parametrize('name', ['../x', '/root/x', 'C:/Windows/x', 'a\\..\\x', 'a/./b', 'a//b', 'x:secret', 'CON.txt', 'a/aux', 'x.', 'x ', 'a\x00b'])
def test_unsafe_paths_rejected(name):
    with pytest.raises(ValueError): safe_member(name)


def test_zip_symlink_duplicate_bomb_and_encryption_rejected():
    for kind in ['symlink', 'duplicate', 'bomb', 'encrypted', 'conflict']:
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z:
            entry = zipfile.ZipInfo('safe.txt')
            if kind == 'symlink':
                entry.create_system = 3; entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(entry, b'hello')
            if kind == 'duplicate': z.writestr('SAFE.TXT', b'other')
            if kind == 'bomb': z.writestr('bomb.txt', b'0' * 1_000_000)
            if kind == 'conflict': z.writestr('safe.txt/child.txt', b'child')
        raw = bytearray(output.getvalue())
        if kind == 'encrypted':
            offset = raw.index(b'PK\x01\x02'); raw[offset + 8] |= 1; raw[6] |= 1
        with pytest.raises(ValueError): zip_entries(bytes(raw))


def test_source_inventory_empty_and_preserved(tmp_path):
    source = tmp_path / 'ccc'; source.mkdir()
    report, _ = inspect_source(source)
    assert report['kind'] == 'DIRECTORY' and report['file_count'] == 0
    for name, raw in synthetic_documents().items(): (source / name).write_bytes(raw)
    before = source_files(source)
    report, _ = inspect_source(source)
    assert report['file_count'] == 3 and all(f['supported'] and f['readable'] for f in report['files'])
    assert source_files(source) == before
    assert file_info('t.txt', b'https://canarytokens.org/test')['existing_canary'] == 'POSSIBLE_EXISTING_TOKEN'


def test_requires_approval_and_rejects_inactive_tokens(system):
    s = system; c = s['client']
    assert c.post('/api/distributions', headers=s['headers'], json={'file_ids': [s['file']['id']]}).status_code == 422
    d = create(s)
    c.post('/api/tokens/' + d['files'][0]['token_id'] + '/deactivate', headers=s['headers']).raise_for_status()
    assert c.get('/api/distributions/' + d['id'] + '/download', headers=s['headers']).status_code == 409


def test_fs_symlink_and_junction_rejected():
    from types import SimpleNamespace
    from backend.archives import no_link
    class Linked:
        def __init__(self, tag, mode): self.tag, self.mode = tag, mode
        def lstat(self): return SimpleNamespace(st_mode=self.mode, st_reparse_tag=self.tag)
    with pytest.raises(ValueError): no_link(Linked(0, stat.S_IFLNK))
    with pytest.raises(ValueError): no_link(Linked(0xA0000003, stat.S_IFDIR))
    assert no_link(Linked(0x9000001A, stat.S_IFDIR))  # OneDrive cloud placeholder, not a path redirection.


def test_corrupt_source_and_duplicate_ids_rejected(system):
    s = system; c = s['client']; body = {'file_ids': [s['file']['id']] * 2, 'approved_test_documents': True}
    assert c.post('/api/distributions', headers=s['headers'], json=body).status_code == 422
    (s['cfg']['runtime'] / 'files' / s['file']['id']).write_bytes(b'changed')
    body['file_ids'] = body['file_ids'][:1]
    assert c.post('/api/distributions', headers=s['headers'], json=body).status_code == 409
