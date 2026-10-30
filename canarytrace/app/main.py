"""추가 서비스의 선택적 app.main:app 진입점입니다.

저장소 루트의 기존 app.main과 별개입니다. canarytrace 디렉터리에서 실행하며,
TLS 설정이 있는 python -m backend.run을 권장합니다.
"""
from backend.app import create_app

app = create_app()
