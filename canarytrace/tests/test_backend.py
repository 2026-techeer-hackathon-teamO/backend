import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from backend.app import create_app
from backend.security import observed_ip, process_classification
from backend.db import now
from conftest import signed, event


def test_registration_metadata_and_hash(system):
    f=system['file']
    assert f['sha256']==hashlib.sha256(system['content']).hexdigest()==f['file_hash']
    assert f['file_id']==f['id'] and f['owner_id']=='admin'
    assert f['classification']=='CONFIDENTIAL' and f['tracking_status']=='TRACKED'
    assert datetime.fromisoformat(f['created_at']).tzinfo


@pytest.mark.parametrize('classification,tracked',[('PUBLIC',False),('INTERNAL',False),('CONFIDENTIAL',True),('RESTRICTED',True)])
def test_classification_policy(system,classification,tracked):
    s=system;c=s['client']
    f=c.post('/api/files',headers=s['headers'],files={'file':('policy.txt',classification.encode())},data={'classification':classification}).json()
    manifest=c.get('/api/agent/manifest',headers={'X-Device-Key':s['device']['device_key']}).json()
    assert (f['id'] in [x['file_id'] for x in manifest['files']])==tracked
    assert 'policy' in manifest


def test_rename_is_same_content(system):
    s=system
    assert s['client'].post('/api/files',headers=s['headers'],files={'file':('renamed.txt',s['content'])}).status_code==409


@pytest.mark.parametrize('method,path',[('get','/api/files'),('get','/api/events'),('get','/api/audit'),('get','/api/stream'),('post','/api/devices'),('get','/api/agent/manifest')])
def test_auth_required(system,method,path):
    assert getattr(system['client'],method)(path).status_code==401


def test_event_metadata_ip_and_dedup(system):
    s=system;c=s['client']; body=event(s)
    r=signed(c,'/api/agent/events',body,s['device'],**{'X-Forwarded-For':'8.8.8.8'})
    assert r.status_code==200,r.text
    assert signed(c,'/api/agent/events',body,s['device']).json()['duplicate']
    rows=c.get('/api/events',headers=s['headers']).json()
    assert len(rows)==1
    row=rows[0]
    assert row['observed_public_ip']=='127.0.0.1' and row['ip_scope']=='NON_PUBLIC_OR_UNKNOWN'
    assert row['local_ip']=='192.168.1.20' and row['device_id']==s['device']['id']
    assert row['device_name']=='TEST-MANAGED-PC' and row['windows_sid']=='S-1-5-21-1'
    assert row['activity']=='INTERACTIVE_PROCESS_CANDIDATE' and not row['human_read_confirmed']
    assert row['file_path'].endswith('renamed.txt') and row['access_type']=='READ_DATA'
    assert row['detected_at'] and row['process_id']=='0x1234'


def test_signature_rejects_modified_body(system):
    s=system
    r=s['client'].post('/api/agent/events',json=event(s),headers={'X-Device-Key':s['device']['device_key'],'X-Event-Timestamp':'1','X-Event-Signature':'bad'})
    assert r.status_code==401
    assert signed(s['client'],'/api/agent/events',event(s),s['device'],**{'X-Event-Signature':'0'*64}).status_code==401


@pytest.mark.parametrize('process,expected',[('MsMpEng.exe','AUTOMATED_SCAN_SUSPECTED'),('SearchIndexer.exe','AUTOMATED_SCAN_SUSPECTED'),('prevhost.exe','PREVIEW_OR_SHELL_CANDIDATE'),('explorer.exe','PREVIEW_OR_SHELL_CANDIDATE'),('notepad.exe','INTERACTIVE_PROCESS_CANDIDATE'),('unknown.exe','FILE_ACCESS_ONLY')])
def test_process_classification(process,expected):
    assert process_classification('C:\\Windows\\'+process)==expected


def test_read_required_and_hash_registered(system):
    s=system
    assert signed(s['client'],'/api/agent/events',event(s,access_mask=2),s['device']).status_code==422
    assert signed(s['client'],'/api/agent/events',event(s,sha256='a'*64),s['device']).status_code==422


@pytest.mark.parametrize('role,status',[('viewer',403),('auditor',403),('admin',200)])
def test_rbac_and_redaction(system,role,status):
    s=system;c=s['client'];signed(c,'/api/agent/events',event(s),s['device'])
    c.post('/api/users',headers=s['headers'],json={'username':'testuser','password':'Long-test-password','role':role}).raise_for_status()
    h={'Authorization':'Bearer '+c.post('/api/login',json={'username':'testuser','password':'Long-test-password'}).json()['access_token']}
    assert c.post('/api/devices',headers=h,json={'name':'denied-or-allowed'}).status_code==status
    data=c.get('/api/events',headers=h).json()[0]
    assert ('windows_user' in data)==(role!='viewer')
    assert ('local_ip' in data)==(role!='viewer')
    if role=='viewer':
        assert c.get('/api/routes',headers=h).status_code==403


def test_device_revocation(system):
    s=system;c=s['client']
    c.post('/api/devices/'+s['device']['id']+'/revoke',headers=s['headers']).raise_for_status()
    assert signed(c,'/api/agent/events',event(s),s['device']).status_code==401


def test_lineage_observed_write(system):
    s=system;c=s['client'];new=hashlib.sha256(b'edited approved document').hexdigest()
    body={'file_id':s['file']['id'],'previous_hash':s['file']['sha256'],'new_hash':new,'record_id':8,'occurred_at':now(),'object_path':'C:\\Approved\\file.txt','file_identity':'1:2','evidence_type':'OBSERVED_4663_WRITE_SAME_FILE_ID'}
    assert signed(c,'/api/agent/lineage',body,s['device']).status_code==200
    assert signed(c,'/api/agent/lineage',body,s['device']).json()['duplicate']
    assert signed(c,'/api/agent/events',event(s,sha256=new),s['device']).status_code==200
    assert len([r for r in c.get('/api/lineage',headers=s['headers']).json() if r['evidence_type']=='OBSERVED_4663_WRITE_SAME_FILE_ID'])==1


def test_all_confidential_files_receive_tokens(system):
    s=system;c=s['client']
    for classification in ['CONFIDENTIAL','RESTRICTED']:
        r=c.post('/api/files',headers=s['headers'],files={'file':(classification+'.txt',classification.encode())},data={'classification':classification})
        assert r.status_code==200,r.text
        f=r.json()
        assert f['token_provisioned'] and len(f['hashes'])==2
        tokens=c.get('/api/tokens',headers=s['headers']).json()
        token=next(t for t in tokens if t['file_id']==f['id'])
        artifact=c.get('/api/tokens/'+token['id']+'/download',headers=s['headers']).content
        assert token['url'].encode() in artifact


@pytest.mark.parametrize('channel',['USB','EMAIL'])
def test_movement_and_route_candidate(system,channel):
    s=system;c=s['client'];d=s['device']
    if channel=='EMAIL':d=c.post('/api/devices',headers=s['headers'],json={'name':'approved-test-gateway','kind':'SMTP_GATEWAY'}).json()
    body={'file_id':s['file']['id'],'sha256':s['file']['sha256'],'external_id':'test-external-1','occurred_at':now(),'channel':channel,'source':'approved-source','destination':'approved-target','evidence_type':'APPROVED_COPY_TOOL' if channel=='USB' else 'SMTP_AUDIT_LOG','evidence_reference':'AUTOMATED_TEST_FIXTURE','usb_device_id':'test-only-usb' if channel=='USB' else None,'copy_observed':channel=='USB'}
    r=signed(c,'/api/integrations/movements',body,d)
    assert r.status_code==200,r.text
    assert signed(c,'/api/integrations/movements',body,d).json()['duplicate']
    assert signed(c,'/api/agent/events',event(s,storage_type='USB' if channel=='USB' else 'LOCAL'),s['device']).status_code==200
    route=c.get('/api/routes',headers=s['headers']).json()[0]
    assert route['correlation']=='IDENTIFIER_AND_TIME_CANDIDATE' and route['route']=='UNKNOWN'
    assert len(route['observed_movements'])==1
    if channel=='EMAIL':assert signed(c,'/api/integrations/movements',body,s['device']).status_code==403


def test_unknown_route_stays_unknown(system):
    s=system;signed(s['client'],'/api/agent/events',event(s),s['device'])
    assert s['client'].get('/api/routes',headers=s['headers']).json()[0]['correlation']=='NONE'


def test_token_requires_approval(system):
    s=system
    assert s['client'].post('/api/tokens',headers=s['headers'],json={'file_id':s['file']['id']}).status_code==422


@pytest.mark.parametrize('mode',['EXPLICIT_LINK_ONLY','WEB_BEACON_HTML'])
def test_canary_and_beacon(system,mode):
    s=system;c=s['client'];body={'file_id':s['file']['id'],'approved_test_document':True,'mode':mode}
    token=c.post('/api/tokens',headers=s['headers'],json=body).json()
    second=c.post('/api/tokens',headers=s['headers'],json=body).json()
    assert token['url']!=second['url'] and token['file_id']==s['file']['id']
    download=c.get('/api/tokens/'+token['id']+'/download',headers=s['headers'])
    assert token['url'].encode() in download.content
    assert b'<script' not in download.content
    assert c.get('/api/events',headers=s['headers']).json()==[]
    from urllib.parse import urlsplit
    response=c.get(urlsplit(token['url']).path)
    assert response.status_code==200
    assert ('image/gif' in response.headers['content-type'])==(mode=='WEB_BEACON_HTML')
    e=c.get('/api/events',headers=s['headers']).json()[0]
    assert e['file_id']==s['file']['id'] and e['observed_public_ip']=='127.0.0.1'
    assert not e['human_read_confirmed'] and 'device_id' not in e
    # 기본 정책: 사내 요청은 기록하지만 외부 경고/Slack 전송 큐를 생성하지 않습니다.
    assert c.get('/api/notifications',headers=s['headers']).json()['records']==[]
    c.post('/api/tokens/'+token['id']+'/deactivate',headers=s['headers'])
    assert c.get(urlsplit(token['url']).path).status_code==404


def test_diagnostics_and_integrity_tamper(system):
    s=system;c=s['client'];body={'external_id':'diag1','code':'COLLECTION_FAILED','detail':'Test fixture permission denial','occurred_at':now()}
    assert signed(c,'/api/agent/diagnostics',body,s['device']).status_code==200
    assert len(c.get('/api/diagnostics',headers=s['headers']).json())==1
    assert c.get('/api/integrity',headers=s['headers']).json()['ok']
    with sqlite3.connect(s['cfg']['runtime']/'dataguard.db') as db:
        db.execute("UPDATE records SET data=json_set(data,'$.classification','PUBLIC') WHERE id=?",(s['file']['id'],))
    result=c.get('/api/integrity',headers=s['headers']).json()
    assert s['file']['id'] in result['invalid'] and not result['ok']


def test_restart_persistence(system):
    s=system;signed(s['client'],'/api/agent/events',event(s),s['device'])
    second=create_app(s['cfg'])
    with TestClient(second,base_url='https://testserver') as c:
        assert len(c.get('/api/events',headers=s['headers']).json())==1
    second.state.engine.dispose()


def test_untrusted_forwarded_ip():
    assert observed_ip('10.0.0.2','1.1.1.1',[])=='10.0.0.2'
    assert observed_ip('10.0.0.2','1.1.1.1',['10.0.0.0/8'])=='1.1.1.1'
    assert observed_ip('10.0.0.2','bad',['10.0.0.0/8'])=='10.0.0.2'


def test_https_enforced(system):
    with TestClient(system['app'],base_url='http://testserver') as c:
        assert c.get('/api/health').status_code==400
