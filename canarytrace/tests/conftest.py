import hashlib
import json
import time
import pytest
from fastapi.testclient import TestClient
from backend.app import create_app
from backend.security import event_signature
from backend.db import now


@pytest.fixture
def system(tmp_path):
    cfg = {'runtime': tmp_path, 'admin_password': 'Test-only-passphrase-2026', 'integrity_key': 'test-integrity-secret-' * 3, 'slack_webhook_url': ''}
    app = create_app(cfg)
    with TestClient(app, base_url='https://testserver', client=('127.0.0.1', 51234)) as c:
        r = c.post('/api/login', json={'username': 'admin', 'password': cfg['admin_password']})
        headers = {'Authorization': 'Bearer ' + r.json()['access_token']}
        content = b'Approved confidential test document. No real personal data.'
        f = c.post('/api/files', headers=headers, files={'file': ('approved.txt', content)}, data={'classification':'CONFIDENTIAL'}).json()
        d = c.post('/api/devices', headers=headers, json={'name':'TEST-MANAGED-PC'}).json()
        yield {'client': c, 'app': app, 'cfg': cfg, 'headers': headers, 'file': f, 'device': d, 'content': content}
    app.state.engine.dispose()


def signed(c, path, body, device, **extra):
    raw = json.dumps(body).encode()
    stamp = str(int(time.time()))
    headers = {'X-Device-Key':device['device_key'], 'X-Event-Timestamp':stamp, 'X-Event-Signature':event_signature(device['device_key'], stamp, path, raw), 'Content-Type':'application/json', **extra}
    return c.post(path, content=raw, headers=headers)


def event(s, **overrides):
    return {'file_id':s['file']['id'], 'sha256':s['file']['sha256'], 'record_id':1234, 'occurred_at':now(), 'pc_name':'TEST-MANAGED-PC', 'windows_user':'TEST\\employee', 'windows_sid':'S-1-5-21-1', 'process':'C:\\Windows\\notepad.exe', 'process_id':'0x1234', 'object_path':'C:\\Approved\\renamed.txt', 'access_mask':1, 'source_type':'WINDOWS_SECURITY_4663', 'local_ip':'192.168.1.20', 'storage_type':'LOCAL', **overrides}


def xml_event(path, *, mask=1, pid=99999, record=55, process='notepad.exe'):
    from xml.sax.saxutils import escape
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4663</EventID><EventRecordID>{record}</EventRecordID><TimeCreated SystemTime="{now()}"/><Computer>TEST-MANAGED-PC</Computer></System><EventData><Data Name="ObjectType">File</Data><Data Name="AccessMask">{mask}</Data><Data Name="SubjectDomainName">TEST</Data><Data Name="SubjectUserName">employee</Data><Data Name="SubjectUserSid">S-1-5-21-1</Data><Data Name="ProcessName">{escape(process)}</Data><Data Name="ProcessId">{pid}</Data><Data Name="ObjectName">{escape(str(path))}</Data></EventData></Event>'''
