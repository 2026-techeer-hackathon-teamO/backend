# backend — 로그 수집 · AI 분석 · 카나리토큰 서버 (FastAPI)

`agent`들이 보낸 DLP 로그를 수집하고, **AI가 해킹/유출 의심 패턴을 판단**해 의심 시 보안 담당자에게 Slack으로 알립니다.
또한 지금까지 유출(다운로드)된 기밀과 **유사한 디코이 파일**을 생성하고, 거기 심은 **카나리토큰**이 열렸을 때 비콘을 수신합니다.

> ⚠️ 방어 보안(DLP·내부자 위협 탐지)용. 인가된 조직 자산 범위 내 운영을 전제로 합니다.

## 기능

| 영역 | 엔드포인트 | 설명 |
|---|---|---|
| 로그 수집 | `POST /api/logs` | agent가 보낸 메일/USB/파일 이벤트 적재 |
| 로그 조회 | `GET /api/logs` | 대시보드용 로그 목록 |
| AI 분석 | `POST /api/analyze` | 로그를 분석해 해킹 의심도 산정 → 의심 시 알림 |
| 알림 | `GET /api/alerts` | 담당자용 의심 이벤트 목록 |
| 디코이 | `GET /api/decoys` · `POST /api/decoys/generate` | 유사 기밀 디코이 파일 + 카나리토큰 생성/배포 |
| 카나리 비콘 | `GET /api/canary/{token_id}` | 디코이 파일이 열리면 호출됨 → opener 정보 기록 + Slack 알림 |

## 실행

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # SLACK_WEBHOOK_URL 등 채우기
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- API 문서: http://localhost:8000/docs
- 헬스체크: http://localhost:8000/health

## 상태 저장

해커톤 스캐폴드라 현재는 **인메모리 저장소**(`app/store.py`)를 사용합니다. 추후 DB(SQLite/Postgres)로 교체하세요.
`analyzer`/`decoy`의 핵심 로직은 TODO 스텁으로 두었습니다 — 실제 규칙/LLM 연동 지점에 주석을 달아두었습니다.

## 관련 레포

- [`agent`](../agent) — Windows 백그라운드 에이전트
- [`frontend`](../frontend) — 보안 담당자 대시보드
