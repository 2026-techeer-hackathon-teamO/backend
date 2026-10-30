"""인증서를 검증하며 서버와 DB 기반 관리자 조회를 확인합니다. 비밀키는 출력하지 않습니다."""
import json
import ssl
from pathlib import Path
import httpx
from dotenv import dotenv_values
ROOT=Path(__file__).resolve().parents[1]
cfg=json.loads((ROOT/'.runtime/settings.json').read_text('utf-8'))
with httpx.Client(base_url=cfg['public_base_url'],verify=ssl.create_default_context(cafile=str(ROOT/'.runtime/tls/cert.pem')),trust_env=False) as c:
    print(c.get('/api/health').json())
    r=c.post('/api/login',json={'username':'admin','password':dotenv_values(ROOT/'.env')['DATAGUARD_ADMIN_PASSWORD']});r.raise_for_status()
    h={'Authorization':'Bearer '+r.json()['access_token']}
    print('Database summary:',c.get('/api/summary',headers=h).json())
    print('Integrity:',c.get('/api/integrity',headers=h).json())
    print('OpenAPI HTTP:',c.get('/openapi.json').status_code)
    c.post('/api/logout',headers=h)
