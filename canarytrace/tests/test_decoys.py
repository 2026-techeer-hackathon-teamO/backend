"""문서 포맷·안전한 다운로드·내외부 판정 회귀 테스트."""
import hashlib
import io
import json
import zipfile
import pytest
from docx import Document
from reportlab.pdfgen import canvas
from pypdf import PdfReader
from backend.security import network_verdict, observed_ip
from backend.db import Record
from conftest import signed,event


def content_for(fmt):
    if fmt=='txt':return b'Approved TEST content'
    out=io.BytesIO()
    if fmt=='docx':
        doc=Document();run=doc.add_paragraph().add_run('Original formatted TEST');run.bold=True;run.italic=True;doc.save(out)
    else:
        c=canvas.Canvas(out);c.drawString(40,700,'Original PDF TEST');c.save()
    return out.getvalue()


@pytest.mark.parametrize('fmt',['docx','pdf','txt'])
def test_document_generation_preservation_and_download(system,fmt):
    s=system;c=s['client'];raw=content_for(fmt)
    r=c.post('/api/files',headers=s['headers'],files={'file':('approved.'+fmt,raw)},data={'classification':'RESTRICTED'})
    assert r.status_code==200,r.text
    file=r.json()
    decoy=next(d for d in c.get('/api/decoys',headers=s['headers']).json() if d['file_id']==file['id'])
    assert all(k in decoy for k in ['decoy_id','file_id','token_id','document_format','classification','created_at','issued_by','tracking_status'])
    assert 'url' not in decoy and 'path' not in decoy
    response=c.get('/api/decoys/'+decoy['id']+'/file',headers=s['headers'])
    assert response.status_code==200,response.text[:100]
    assert 'attachment' in response.headers['content-disposition']
    assert hashlib.sha256(response.content).hexdigest()==decoy['sha256']
    if fmt=='docx':
        doc=Document(io.BytesIO(response.content))
        assert doc.paragraphs[0].text=='Original formatted TEST'
        assert doc.paragraphs[0].runs[0].bold and doc.paragraphs[0].runs[0].italic
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            assert b'https://localhost:8443/t/' in z.read('word/_rels/document.xml.rels')
            assert not any('vbaProject' in n for n in z.namelist())
    elif fmt=='pdf':
        pdf=PdfReader(io.BytesIO(response.content))
        assert len(pdf.pages)==2 and 'Original PDF TEST' in pdf.pages[0].extract_text()
        assert '/Annots' in pdf.pages[1]
    else:
        assert response.content.startswith(raw) and b'https://localhost:8443/t/' in response.content
    assert any(a['action']=='DECOY_DOWNLOADED' for a in c.get('/api/audit',headers=s['headers']).json())


def decoy(system):return system['client'].get('/api/decoys',headers=system['headers']).json()[0]


def test_download_auth_and_role(system):
    s=system;c=s['client'];d=decoy(s);url='/api/decoys/'+d['id']+'/file'
    assert c.get(url).status_code==401
    c.post('/api/users',headers=s['headers'],json={'username':'auditor','password':'long-auditor-password','role':'auditor'})
    h={'Authorization':'Bearer '+c.post('/api/login',json={'username':'auditor','password':'long-auditor-password'}).json()['access_token']}
    assert c.get('/api/decoys',headers=h).status_code==200
    assert c.get(url,headers=h).status_code==403


@pytest.mark.parametrize('identifier',['unknown','..%5c..%5c.env','%2e%2e%2f.env','C:%5cWindows%5cwin.ini'])
def test_missing_and_path_traversal(system,identifier):
    assert system['client'].get('/api/decoys/'+identifier+'/file',headers=system['headers']).status_code==404


@pytest.mark.parametrize('mode',['missing','changed'])
def test_download_artifact_failure_audited(system,mode):
    s=system;c=s['client'];d=decoy(s);path=s['cfg']['runtime']/'files'/d['token_id']
    if mode=='missing':path.unlink()
    else:path.write_bytes(b'tampered')
    r=c.get('/api/decoys/'+d['id']+'/file',headers=s['headers'])
    assert r.status_code==500 and str(s['cfg']['runtime']) not in r.text
    assert c.get('/api/audit',headers=s['headers']).json()[0]['action']=='DECOY_DOWNLOAD_FAILED'


def test_inactive_decoy_and_rate_limit(system):
    s=system;c=s['client'];d=decoy(s)
    c.post('/api/tokens/'+d['token_id']+'/deactivate',headers=s['headers'])
    assert c.get('/api/decoys/'+d['id']+'/file',headers=s['headers']).status_code==403


@pytest.mark.parametrize('address,networks,scanner,expected',[
    ('10.10.2.1',['10.10.0.0/16'],False,'INTERNAL_ACCESS'),
    ('192.168.2.1',['10.10.0.0/16'],False,'EXTERNAL_ACCESS'),
    ('8.8.8.8',['10.10.0.0/16'],False,'EXTERNAL_ACCESS'),
    ('2001:db8::2',['2001:db8::/32'],False,'INTERNAL_ACCESS'),
    ('UNKNOWN',[],False,'UNKNOWN_NETWORK'),
    ('8.8.8.8',[],True,'SUSPECTED_SCANNER')])
def test_network_classification(address,networks,scanner,expected):
    assert network_verdict(address,networks,scanner=scanner)==expected


def test_proxy_boundary():
    assert observed_ip('10.0.0.1','8.8.8.8, 192.168.0.2',['10.0.0.0/8'])=='192.168.0.2'
    assert observed_ip('10.0.0.1','8.8.8.8, 10.0.0.2',['10.0.0.0/8'])=='8.8.8.8'
    assert observed_ip('::ffff:10.0.0.1','2001:db8::2',['10.0.0.0/8'])=='2001:db8::2'


@pytest.mark.parametrize('network,scanner,alerts',[('internal',False,False),('external',False,True),('external',True,False),('blocked',False,True)])
def test_network_alert_policy(system,network,scanner,alerts):
    s=system;c=s['client']
    policy={'allowed_networks':['127.0.0.0/8'] if network=='internal' else ['10.10.0.0/16'],'blocked_networks':['127.0.0.0/8'] if network=='blocked' else []}
    c.put('/api/policy',headers=s['headers'],json=policy).raise_for_status()
    token=c.get('/api/tokens',headers=s['headers']).json()[0]
    from urllib.parse import urlparse
    c.get(urlparse(token['url']).path,headers={'User-Agent':'Proofpoint scanner' if scanner else 'Approved Test Browser','X-Forwarded-For':'10.10.1.2'})
    e=c.get('/api/events',headers=s['headers']).json()[0]
    assert e['observed_public_ip']=='127.0.0.1'
    assert bool(c.get('/api/alerts',headers=s['headers']).json())==alerts
    assert bool(c.get('/api/notifications',headers=s['headers']).json()['records'])==alerts
    assert e['event_confidence']=='CONFIRMED_BEACON_REQUEST'
    if scanner:assert e['network_verdict']=='SUSPECTED_SCANNER'
    if network=='blocked':assert e['network_verdict']=='POLICY_VIOLATION'


def test_tracking_switch_and_investigation_timeline(system):
    s=system;c=s['client'];body=event(s)
    r=signed(c,'/api/agent/events',body,s['device']);r.raise_for_status()
    event_id=r.json()['event_id']
    c.post('/api/events/'+event_id+'/investigation',headers=s['headers'],json={'status':'BENIGN','note':'승인된 로컬 시험'}).raise_for_status()
    timeline=c.get('/api/files/'+s['file']['id']+'/timeline',headers=s['headers']).json()
    assert {'registration','decoy','event','investigation'}.issubset({r['kind'] for r in timeline})
    c.put('/api/policy',headers=s['headers'],json={'canary_tracking_enabled':False}).raise_for_status()
    token=c.get('/api/tokens',headers=s['headers']).json()[0]
    from urllib.parse import urlparse
    assert c.get(urlparse(token['url']).path).status_code==404


def test_legacy_generate_path(system):
    s=system
    r=s['client'].post('/api/decoys/generate',headers=s['headers'],json={'file_id':s['file']['id'],'approved_test_document':True})
    assert r.status_code==200,r.text
    assert r.json()['download_url'].endswith('/file')


def test_download_rate_limit(system):
    s=system;c=s['client'];d=decoy(s)
    codes=[c.get('/api/decoys/'+d['id']+'/file',headers=s['headers']).status_code for _ in range(31)]
    assert codes[:30]==[200]*30 and codes[-1]==429


def test_external_alerts_can_be_disabled(system):
    s=system;c=s['client']
    c.put('/api/policy',headers=s['headers'],json={'allowed_networks':['10.10.0.0/16'],'canary_external_alerts':False}).raise_for_status()
    token=c.get('/api/tokens',headers=s['headers']).json()[0]
    from urllib.parse import urlparse
    c.get(urlparse(token['url']).path)
    assert c.get('/api/events',headers=s['headers']).json()[0]['network_verdict']=='EXTERNAL_ACCESS'
    assert c.get('/api/alerts',headers=s['headers']).json()==[]
