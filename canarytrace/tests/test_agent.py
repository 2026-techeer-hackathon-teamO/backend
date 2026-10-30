"""합성 XML/장치 응답을 사용하는 자동 테스트. 실제 Windows 통합 검증과 구분합니다."""
import hashlib
import json
import os
from pathlib import Path
import httpx
import pytest
from agent.windows_agent import Agent, parse_4663, sha256
from conftest import xml_event


@pytest.fixture
def agent(tmp_path):
    root=tmp_path/'approved';root.mkdir()
    path=root/'original.txt';path.write_text('Approved file')
    cfg=tmp_path/'agent.json';cfg.write_text(json.dumps({'server':'https://testserver','device_id':'test-device','device_key':'test-key','roots':[str(root)]}))
    a=Agent(cfg)
    a.manifest={sha256(path):{'file_id':'registered-id','hashes':[sha256(path)]}}
    a.prime()
    yield a,path
    a.close()


def test_parse_user_pc_and_access():
    e=parse_4663(xml_event('C:\\Approved\\test.txt'))
    assert e['pc_name']=='TEST-MANAGED-PC' and e['windows_sid']=='S-1-5-21-1'
    assert e['windows_user']=='TEST\\employee' and e['access_mask']==1


@pytest.mark.parametrize('change',[('4663','4656'),('Microsoft-Windows-Security-Auditing','Other-Provider'),('>File<','>Directory<')])
def test_rejects_other_events(change):
    assert parse_4663(xml_event('test.txt').replace(*change)) is None


def test_no_metadata_only_as_read():
    assert parse_4663(xml_event('test.txt',mask=128)) is None


def test_real_hash_and_renamed_file(agent,monkeypatch):
    a,path=agent;monkeypatch.setattr('agent.windows_agent.storage_info',lambda _: {'storage_type':'LOCAL','volume_id':'test','usb_device_id':None})
    renamed=path.with_name('renamed.txt');path.rename(renamed)
    event=a.prepare(xml_event(renamed))
    assert event['file_id']=='registered-id' and event['sha256']==hashlib.sha256(renamed.read_bytes()).hexdigest()


def test_own_hash_reads_excluded(agent):
    a,path=agent
    assert a.prepare(xml_event(path,pid=os.getpid())) is None


def test_normal_file_and_unapproved_root_excluded(agent):
    a,path=agent
    normal=path.with_name('ordinary.txt');normal.write_text('Not registered')
    assert a.prepare(xml_event(normal)) is None
    outside=path.parent.parent/'outside.txt';outside.write_text(path.read_text())
    assert a.prepare(xml_event(outside)) is None


def test_observed_write_creates_lineage_not_read(agent):
    a,path=agent
    path.write_text('Changed approved document')
    assert a.prepare(xml_event(path,mask=2)) is None
    pending=a.db.execute('SELECT path,payload FROM pending').fetchall()
    assert pending[0][0]=='/api/agent/lineage'
    assert json.loads(pending[0][1])['new_hash']==sha256(path)


def test_unobserved_modification_not_linked(agent):
    a,path=agent;path.write_text('Changed without observed write')
    assert a.prepare(xml_event(path)) is None
    assert a.db.execute("SELECT COUNT(*) FROM pending WHERE path='/api/agent/lineage'").fetchone()[0]==0
    assert a.db.execute("SELECT COUNT(*) FROM pending WHERE path='/api/agent/diagnostics'").fetchone()[0]==1


def test_durable_outbox_survives_network_failure_and_restart(agent):
    a,path=agent
    a.enqueue('/api/agent/events',{'test':'fixture'},'event-1');a.db.commit()
    a.client.close();a.client=httpx.Client(base_url='https://testserver',transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    with pytest.raises(httpx.HTTPStatusError):a.flush()
    second=Agent(a.config_path)
    try:
        assert second.db.execute('SELECT COUNT(*) FROM pending').fetchone()[0]==1
        def success(request):
            assert request.headers['x-event-signature']
            return httpx.Response(200,json={'duplicate':True,'event_id':'same-id'})
        second.client.close();second.client=httpx.Client(base_url='https://testserver',transport=httpx.MockTransport(success))
        second.flush()
        assert second.db.execute('SELECT COUNT(*) FROM pending').fetchone()[0]==0
    finally:second.close()


def test_permanent_rejection_does_not_block_outbox(agent):
    a,path=agent;a.enqueue('/api/agent/events',{},'bad');a.db.commit()
    a.client.close();a.client=httpx.Client(base_url='https://testserver',transport=httpx.MockTransport(lambda r:httpx.Response(422,json={'detail':'invalid'})))
    a.flush()
    assert a.db.execute('SELECT COUNT(*) FROM rejected').fetchone()[0]==1


def test_non_usb_copy_rejected(agent,monkeypatch):
    a,path=agent;monkeypatch.setattr(a,'refresh',lambda:None)
    class Storage:
        def __call__(self,_):return {'storage_type':'LOCAL'}
        def cache_clear(self):pass
    monkeypatch.setattr('agent.windows_agent.storage_info',Storage())
    with pytest.raises(ValueError,match='USB bus'):
        a.copy_usb(path,path.with_name('copy.txt'))
