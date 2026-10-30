# backend — 로그 수집 · AI 분석 · 카나리토큰 서버 (FastAPI)

`agent`들이 보낸 DLP 로그를 수집하고, **AI가 해킹/유출 의심 패턴을 판단**해 의심 시 보안 담당자에게 Slack으로 알립니다.
또한 지금까지 유출(다운로드)된 기밀과 **유사한 디코이 파일**을 생성하고, 거기 심은 **카나리토큰**이 열렸을 때 비콘을 수신합니다.

> ⚠️ 방어 보안(DLP·내부자 위협 탐지)용. 인가된 조직 자산 범위 내 운영을 전제로 합니다.

## 기능

| 영역 | 엔드포인트 | 설명 |
|---|---|---|
| 로그 수집 | `POST /api/logs` | agent가 보낸 메일/USB/파일 이벤트 적재 |
| 로그 조회 | `GET /api/logs` · `GET /api/logs/{id}` | 대시보드용 로그 목록(필터·페이지네이션) / 단건 조회 |
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

- **로그**: SQLite 파일(`DB_PATH`, 기본 `dlp.db`)에 저장되어 재시작해도 유지됩니다 (`app/db.py`).
- **알림 · 디코이 · 카나리 히트**: 아직 **인메모리 저장소**(`app/store.py`)입니다. 재시작 시 초기화됩니다.

`analyzer`/`decoy`의 핵심 로직은 TODO 스텁으로 두었습니다 — 실제 규칙/LLM 연동 지점에 주석을 달아두었습니다.

## 로그 조회 API

`GET /api/logs` — 최신순. 필터에 걸린 전체 건수는 `X-Total-Count` 응답 헤더로 반환합니다.

| 쿼리 | 설명 |
|---|---|
| `host`, `user`, `classification` | 정확히 일치 |
| `event_type` | `file_access` · `email_send` · `usb_copy` · `blocked` |
| `blocked` | `true` / `false` |
| `since`, `until` | 수신 시각 범위 (ISO8601, 시간대 없으면 UTC) |
| `limit`, `offset` | 기본 100 / 0, `limit`은 1~1000 |

예: `GET /api/logs?host=PC-01&event_type=usb_copy&since=2026-10-01T00:00:00Z&limit=20&offset=20`

## 테스트

```bash
pip install -r requirements-dev.txt
pytest
```

## 관련 레포

- [`agent`](../agent) — Windows 백그라운드 에이전트
- [`frontend`](../frontend) — 보안 담당자 대시보드
