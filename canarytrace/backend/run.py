import json
import os
import asyncio
from pathlib import Path
import uvicorn
from .app import ROOT, create_app


def loop_factory(use_subprocess=False):
    # Windows Proactor의 브라우저 SSE 종료 시 ConnectionReset 콜백 오류를 피합니다.
    # 서버 내부에서 비동기 자식 프로세스를 실행하지 않는 단일 프로세스 구성입니다.
    return asyncio.SelectorEventLoop() if os.name == 'nt' else asyncio.new_event_loop()

if __name__ == '__main__':
    runtime = Path(os.getenv('DATAGUARD_RUNTIME', ROOT / '.runtime'))
    cfg = json.loads((runtime / 'settings.json').read_text('utf-8'))
    uvicorn.run(create_app(), host=cfg.get('bind_host', '127.0.0.1'), port=cfg.get('port', 8443), ssl_keyfile=str(runtime / 'tls' / 'key.pem'), ssl_certfile=str(runtime / 'tls' / 'cert.pem'), proxy_headers=False, access_log=False, loop='backend.run:loop_factory')
