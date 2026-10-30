"""시작 스크립트가 단순 PID 생성 대신 실제 TLS 서버 준비 상태를 확인하도록 합니다."""
import json
import ssl
import time
from pathlib import Path
import httpx
ROOT=Path(__file__).resolve().parents[1]
cfg=json.loads((ROOT/'.runtime/settings.json').read_text('utf-8'))
with httpx.Client(base_url=cfg['public_base_url'],verify=ssl.create_default_context(cafile=str(ROOT/'.runtime/tls/cert.pem')),trust_env=False,timeout=2) as c:
    for _ in range(20):
        try:
            r=c.get('/api/health')
            if r.status_code==200 and r.json().get('service')=='DataGuard':
                print('HTTPS 서버 준비 확인 완료')
                raise SystemExit(0)
        except httpx.HTTPError:
            pass
        time.sleep(1)
raise SystemExit('서버가 준비되지 않았습니다. .runtime/logs/server.stderr.log를 확인하세요.')
