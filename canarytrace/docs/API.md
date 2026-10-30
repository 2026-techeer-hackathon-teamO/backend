# API 및 정책

운영 주소는 기본 `https://localhost:8443`이며 OpenAPI는 `/docs`에 있다. 모든 관리자 API는 `/api/login`에서 얻은 `Authorization: Bearer ...`가 필요하다. 세션은 8시간이며 로그아웃 시 폐기한다. 프론트엔드는 이 PR에 포함하지 않는다. 클라이언트는 Bearer 인증과 SSE 갱신 계약에 맞춰 연동해야 한다.

## 주요 API

| 메서드 / 경로 | 권한 / 동작 |
|---|---|
| POST `/api/files` | admin, multipart 등록. CONFIDENTIAL/RESTRICTED는 토큰 사본 자동 생성 |
| GET `/api/files` | 인증 사용자, 파일 목록 |
| POST `/api/tokens` | admin, 등록 file_id·승인 true·모드. 추가 토큰 생성 |
| GET `/api/tokens` | admin, 기존 호환 토큰 관리 API |
| POST `/api/tokens/{id}/deactivate` | admin, 토큰 및 디코이 비활성화 |
| POST `/api/decoys/generate` | admin, `{file_id, approved_test_document:true, mode}`. 기존 경로 유지 |
| GET `/api/decoys` | admin/auditor, 토큰 비밀 URL·내부 저장 경로 없는 메타데이터 |
| GET `/api/decoys/{id}/file` | admin, 디코이 사본 다운로드, 1분당 계정별 30회 제한 |
| GET `/t/{secret}` | 공개 랜덤 토큰 URL 요청. 실제 요청만 기록 |
| GET `/b/{secret}` | 공개 이미지 비콘. DOCX 원격 리소스는 표시용 PNG, 링크/HTML 비콘은 GIF |
| GET `/api/canary/{secret}` | 기존 카나리 이미지 경로 호환. 공개 비밀 토큰 사용 |
| GET `/api/events` | 관리자/감사자 상세, viewer는 사용자·IP·장치 정보 제거 |
| GET `/api/files/{id}/timeline` | admin/auditor, 등록부터 조사까지 통합 이력 |
| POST `/api/events/{event_id}/investigation` | admin/auditor, OPEN/BENIGN/ESCALATED/RESOLVED와 note 저장 |
| GET `/api/stream` | 인증, SSE 갱신 번호. 세션 만료·로그아웃 시 종료 |
| GET/PUT `/api/policy` | 읽기 인증/수정 admin, CIDR·경고·추적·보관 정책 |
| GET `/api/integrity` | admin, 레코드 HMAC 점검 |
| GET `/api/alerts`, `/api/notifications` | admin/auditor, 경고·Slack 상태 |
| POST `/api/devices` | admin, 장치/SMTP 커넥터 키 일회 발급 |
| GET `/api/agent/manifest` | 장치 인증, 기밀파일 해시·정책 동기화 |
| POST `/api/agent/events`, `/api/agent/lineage`, `/api/agent/diagnostics` | 인증·서명된 장치 요청 |
| POST `/api/integrations/movements` | 채널별 허용 커넥터만 수신 |
| GET `/api/logs`, POST `/api/logs`, POST `/api/analyze`, GET `/health` | 추가 서비스의 호환 경로. 원래 저장소 서버와 쓰기 요청 스키마/인증 계약이 다름 |

다운로드: 401 인증 없음, 403 권한 부족/비활성, 404 잘못된 ID, 429 속도 제한. 저장 파일 누락·해시 불일치·메타데이터 변조는 500 일반 오류와 `DECOY_DOWNLOAD_FAILED` 감사 기록을 남긴다. 파일 경로를 사용자 입력으로 받지 않는다. 검증한 바이트를 직접 응답하여 파일 재열기 사이 변경을 방지한다. 정상 응답은 형식별 MIME과 `Content-Disposition: attachment`이며 다운로드 감사에 파일 ID·해시를 남긴다. 다운로드 문서 자체에는 기능상 토큰 URL이 포함되지만 URL/헤더에 내부 저장 경로를 넣지 않는다.

## IP 판정

`.env`의 `CORPORATE_NETWORKS`, `CANARY_EXTERNAL_ALERTS`, `CANARY_TRACKING_ENABLED`는 최초 정책 생성 기본값이다. 생성 후에는 DB 정책/관리자 화면이 우선한다. 승인된 프록시는 `.runtime/settings.json`의 `trusted_proxies`로 설정한다. 기본은 빈 목록이며 `X-Forwarded-For`를 신뢰하지 않는다. 프록시 체인은 오른쪽부터 신뢰 경계를 따라 처리한다.

- `INTERNAL_ACCESS`: 설정한 승인 CIDR에 포함. 사원 신원 확정 아님. 감사 기록만, 외부 경고 기본 억제.
- `EXTERNAL_ACCESS`: 승인 CIDR 밖. 사설/루프백이라도 정책상 외부일 수 있다. 인터넷 공인 IP라는 뜻이 아니다.
- `UNKNOWN_NETWORK`: 주소 해석 불가. 별도 감사와 검토 대상.
- `SUSPECTED_SCANNER`: HEAD 또는 알려진 user-agent 단서. 인간의 열람 확정 금지, 기본 외부 알림 억제.
- `POLICY_VIOLATION`: 명시적 차단 CIDR에 해당하는 비스캐너 요청.

외부/차단망 비콘은 경고와 Slack 큐를 생성한다. 내부·스캐너 요청은 이벤트를 기록하되 기본 경고를 만들지 않는다. IP는 실제 TLS 연결 peer를 기준으로 하고 승인된 프록시가 있을 때만 전달 주소를 채택한다. 공인 주소가 아닌 경우 UI에 사설/루프백으로 표시한다.

## 장치 요청 무결성

장치 키로 인증하고 SHA-256(장치 키)를 키로 사용한 HMAC-SHA256 서명을 검증한다. 서명 입력은 `timestamp + '\n' + request_path + '\n' + raw_body`이며 허용 시간차는 5분이다. 키는 서버 DB에 해시로만 저장하고, 장치 구성 파일은 ACL로 제한한다. 같은 장치·4663 레코드·발생시각은 중복 저장하지 않는다. 재전송 때 원본 사건 시각을 유지하고 전송 서명 시각만 갱신한다. 단말이 침해되면 그 단말의 보고 신뢰성까지 보장할 수 없다.

## Slack

`.env`에 승인된 `SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...`을 설정한 뒤 서버를 재시작한다. Webhook URL은 DB와 UI에 노출하지 않는다. 전송 상태는 PENDING/RETRY/SENT/FAILED/NOT_CONFIGURED이며 실제 `200 ok` 응답만 SENT로 기록한다. 일시 오류는 최대 5회 재시도한다. 전송 후 연결이 끊기면 중복 도착 가능성이 있으므로 알림의 event_id로 확인한다. 외부 AI API는 호출하지 않는다.

## 배포본 및 관측 API

| 메서드 / 경로 | 권한 / 동작 |
|---|---|
| GET `/api/sources/ccc` | admin, 실제 Windows Desktop의 ccc 후보·원본 fingerprint 조회 |
| POST `/api/sources/ccc/import` | admin, 선택한 source_id/fingerprint 및 테스트 문서 승인 필요 |
| POST/GET `/api/distributions` | admin 생성 / 인증된 배포본 목록 |
| GET `/api/distributions/{id}` | 배포본별 이벤트와 증거 등급 그래프 |
| GET `/api/distributions/{id}/download` | 인증·권한·무결성 검사 후 ZIP 다운로드 및 감사 기록 |
| POST `/api/agent/observations` | 장치 인증·서명된 USB/복사/추출/이름 변경 관측 |
| GET `/api/observations`, `/api/routes` | 인증 및 역할별 개인정보 필터 |

파일 등록, 다운로드, 추출, 파일 읽기, 비콘 요청은 서로 다른 증거다. 다운로드만으로 추출이나 열람을 확정하지 않는다. PC/사용자/프로세스는 인증된 장치 보고에만 있으며 비콘만으로는 제공되지 않는다.
