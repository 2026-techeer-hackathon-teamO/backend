# backend — 로그 수집 · AI 분석 · 카나리토큰 서버 (FastAPI)

`agent`들이 보낸 DLP 로그를 수집하고, **AI가 해킹/유출 의심 패턴을 판단**해 의심 시 보안 담당자에게 Slack으로 알립니다.
또한 지금까지 유출(다운로드)된 기밀과 **유사한 디코이 파일**을 생성하고, 거기 심은 **카나리토큰**이 열렸을 때 비콘을 수신합니다.

> ⚠️ 방어 보안(DLP·내부자 위협 탐지)용. 인가된 조직 자산 범위 내 운영을 전제로 합니다.

## 기능

| 영역 | 엔드포인트 | 설명 |
|---|---|---|
| 로그 수집 | `POST /api/logs` | agent가 보낸 메일/USB/파일 이벤트 적재. `file_hash`가 디코이와 일치하면 즉시 Slack |
| 로그 조회 | `GET /api/logs` · `GET /api/logs/{id}` | 대시보드용 로그 목록(필터·페이지네이션) / 단건 조회 |
| AI 분석 | `POST /api/analyze` | 로그 하나를 규칙 + 해킹 패턴 AI로 분석만 해봄 (저장·알림 없음, 시연용) |
| 알림 | `GET /api/alerts` | 담당자용 의심 이벤트 목록 |
| 디코이 | `POST /api/decoys` · `GET /api/decoys` · `POST /api/decoys/generate` | AI가 만든 디코이 파일 업로드 / 목록 / (파일 없이) 레코드+카나리 URL 생성 |
| agent 전용 | `GET /api/agent/decoys` · `GET /api/agent/decoys/{id}/file` | 배치할 디코이 목록·파일 (알림 없음, 데모용으로 인증 없음) |
| 카나리 비콘 | `GET /api/canary/{token_id}` | 디코이 파일이 열리면 호출됨 → opener 정보 기록 + Slack 알림 |

## 디코이 · 카나리토큰 설계

카나리토큰은 **실제 기밀 파일이 아니라 디코이(미끼) 파일에만** 심습니다.
정상 업무에서 열 일이 없는 파일이라, 열렸다는 것 자체가 탈취·반출 신호가 됩니다.

### 역할 분담

| 단계 | 담당 | 비고 |
|---|---|---|
| 토큰 ID 발급 · 비콘 URL 생성 | backend | `build_decoy()` → `{CANARY_BASE_URL}/api/canary/{token_id}` |
| 유출 기밀과 유사한 디코이 파일 생성 | AI 담당 팀원 | `POST /api/decoys`로 업로드 → backend가 저장 + SHA-256 계산 |
| 디코이 파일에 비콘 임베드 | 미정 (TODO) | 아래 참고 |
| 디코이를 내려받아 사용자 다운로드 폴더에 배치 | agent | `GET /api/agent/decoys/{id}/file` (알림 없음) |
| 디코이 반출 감지 | backend | agent 로그의 `file_hash`가 디코이 해시와 일치하면 HIGH 알림 |
| 비콘 수신 · 기록 · 알림 | backend | `GET /api/canary/{token_id}` |

토큰 발급과 비콘 수신(`token_id` → 디코이 조회)이 같은 저장소를 써야 하므로 토큰은 backend가 발급합니다.
그러면 토큰 생성 로직이 직원 PC에 노출되지도 않습니다.

> **TODO — 비콘 임베드 흐름:** 지금은 `POST /api/decoys`(업로드)가 새 `token_id`를 발급하므로,
> 파일 안에 미리 심은 비콘 URL의 토큰과 등록된 토큰이 달라집니다.
> 업로드 전에 토큰·URL을 먼저 발급받아 임베드한 뒤 같은 디코이에 파일을 올리는 흐름이 필요합니다.

### 알림 조건: 회사 밖에서 열렸을 때만 (TODO)

- 비콘을 보낸 IP가 **사내 IP 대역 밖**일 때만 Slack 알림을 보냅니다.
- 사내에서 열린 기록도 `CanaryHit`으로 남겨 감사용으로 씁니다. 단, 알림은 보내지 않습니다.
- IP를 알 수 없거나 파싱에 실패하면 외부로 간주해 알림을 보냅니다 (fail-safe).
- 사내 열람·반출은 agent의 메일/USB/파일 로그로 탐지합니다. 카나리는 "회사 밖에서 열림"이라는 마지막 신호용입니다.

### 모든 파일에 심지 않는 이유

| 문제 | 설명 |
|---|---|
| 오탐 폭증 | 정상 업무 열람마다 비콘이 울려 탐지 신호로서 의미가 없어짐 |
| 원본 훼손 | 비콘을 임베드하려면 원본을 수정해야 함 (서명·해시 검증이 깨질 수 있음) |
| 포맷 한계 | docx/xlsx/pdf/html 정도만 가능. txt·csv·이미지·소스코드는 사실상 불가 |
| 쉽게 무력화 | 오프라인 열람이나 외부 리소스를 차단하는 뷰어로 열면 울리지 않음 |
| 프라이버시 | 직원의 모든 열람이 IP·UA와 함께 서버로 전송되어 사내 감시 이슈가 생김 |

## 실행

### 1. 설치

Python 3.11 이상이 필요합니다.

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt                     # 의존성이 바뀌면(git pull 후 등) 다시 실행
```

### 2. 환경 변수 (`.env`)

```bash
cp .env.example .env
```

| 변수 | 필수 | 설명 |
|---|---|---|
| `ANTHROPIC_API_KEY` | 선택 | 해킹 패턴 AI(Claude) 키. **비우면 규칙 기반 분석만** 동작 |
| `AI_MODEL` | 선택 | 판단에 쓸 Claude 모델 (기본 `claude-opus-5-5`) |
| `SLACK_WEBHOOK_URL` | 선택 | 보안 담당자 알림용 Slack Incoming Webhook. **비우면 서버 콘솔에 출력** |
| `CANARY_BASE_URL` | 선택 | 디코이 파일에 심을 카나리 비콘 베이스 URL (기본 `http://localhost:8000`) |
| `DB_PATH` | 선택 | 로그·디코이 SQLite 파일 (기본 `dlp.db`) |
| `DECOY_STORE_DIR` | 선택 | 업로드된 디코이 파일 폴더 (기본 `decoys_store`) |
| `CORS_ORIGINS` | 선택 | 프론트 개발 서버 주소, 쉼표로 여러 개 (기본 `http://localhost:5173`) |

아무것도 채우지 않아도 서버는 뜹니다. 이 경우 AI 대신 규칙으로 판단하고, 알림은 Slack 대신 콘솔에 찍힙니다.

### 3. 서버 실행

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- API 문서(Swagger): http://localhost:8000/docs
- 헬스체크: http://localhost:8000/health

### 4. 해킹 패턴 AI 동작 확인

기밀 파일을 USB로 복사하는 로그를 보낸 뒤 알림을 조회합니다. 분석은 백그라운드에서 돌기 때문에 AI 판단은 몇 초 걸립니다.

```bash
curl -X POST localhost:8000/api/logs -H 'Content-Type: application/json' \
  -d '{"host":"PC-01","user":"kim","event_type":"usb_copy","file_name":"2026_인사평가.xlsx","classification":"confidential","channel":"usb:E:"}'

sleep 5
curl localhost:8000/api/alerts
```

응답의 `analyzed_by`로 누가 판단했는지 확인합니다.

| `analyzed_by` | 의미 |
|---|---|
| `ai` | Claude가 판단함 (`ANTHROPIC_API_KEY` 설정됨) |
| `rule` | 규칙으로 판단함 (키 없음, 또는 AI 호출 실패 → 서버 콘솔에 `[ai_analyzer] ...` 로그) |
| `decoy` | 디코이 파일 해시와 일치 |

저장 없이 판단 결과만 보고 싶으면 `POST /api/analyze`에 같은 본문을 보내면 됩니다 (바로 응답, 알림·Slack 없음).

### 5. 테스트

```bash
pip install -r requirements-dev.txt
pytest
```

테스트는 실제 Claude API를 호출하지 않습니다.

## 상태 저장

- **로그**: SQLite 파일(`DB_PATH`, 기본 `dlp.db`)에 저장되어 재시작해도 유지됩니다 (`app/db.py`).
- **디코이**: 같은 SQLite의 `decoys` 테이블, 파일 본문은 `DECOY_STORE_DIR`(기본 `decoys_store/`)에 id 이름으로 저장.
- **알림 · 카나리 히트**: 아직 **인메모리 저장소**(`app/store.py`)입니다. 재시작 시 초기화됩니다.


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

## 해킹 패턴 AI 판단

`POST /api/logs`로 들어온 로그는 응답 후 **백그라운드**에서 분석됩니다 (`app/services/analyzer.py`, `ai_analyzer.py`).

1. 규칙 기반 스코어링 (기밀 메일/USB 반출, 같은 PC 기밀 다수 접근, 차단 이벤트)
2. 메일·USB·차단 이벤트이거나 규칙 신호가 있으면, 같은 PC의 최근 로그(최대 30건)와 함께 **Claude(`AI_MODEL`, 기본 `claude-opus-5-5`)** 가 최종 판정
   - 구조화 출력(JSON 스키마)으로 `suspicious` · `severity` · `score` · `reason` · `patterns`를 받음
   - `suspicious`이고 `score ≥ 0.5`면 알림 + Slack. AI가 정상이라고 보면 규칙이 의심해도 알리지 않음
   - 분류기 거절 시 서버 측 fallback(`fallbacks: "default"`)으로 다른 모델이 재시도
3. `ANTHROPIC_API_KEY`가 없거나 API 오류·거절·형식 오류면 규칙 결과로 판정

알림의 `analyzed_by`로 출처를 구분합니다: `rule`(규칙) · `ai`(해킹 패턴 AI) · `decoy`(디코이 해시 매칭).

## 디코이 반출 감지 흐름

```
AI(팀원) ── POST /api/decoys (multipart file) ──▶ backend: 저장 + SHA-256 계산
agent    ── GET /api/agent/decoys[/{id}/file] ─▶ 사용자 다운로드 폴더에 몰래 배치 (알림 없음)
agent    ── POST /api/logs {file_hash} ────────▶ 디코이 해시와 일치 → HIGH 알림 + Slack
외부 PC  ── GET /api/canary/{token_id} ────────▶ 디코이가 열림 → Slack
```

- agent는 메일/USB/파일 이벤트의 `file_hash`에 **파일 내용의 SHA-256(hex)** 을 넣어야 합니다 (대소문자 무관).
- agent 전용 API는 데모용으로 **인증이 없습니다**. 누구나 디코이 목록(파일명·해시)을 볼 수 있어 실제 배포 전에는 agent 인증을 붙여야 합니다.
- agent 쪽 연동 가이드: `../agent/DECOY_INTEGRATION.md`

```bash
# 테스트용 디코이 업로드
curl -X POST localhost:8000/api/decoys -F "file=@fake.xlsx;filename=2026_인사평가_기밀.xlsx" -F based_on_hash=<원본해시>
```

## 관련 레포

- [`agent`](../agent) — Windows 백그라운드 에이전트
- [`frontend`](../frontend) — 보안 담당자 대시보드
