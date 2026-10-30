# PR 검증 기록

검증일: 2026-10-31. 환경: Windows, Python 3.11.9, Windows PowerShell 5.1. 실제 사용자·장치 식별정보, 인증정보, 원본 문서 및 실행 DB는 이 문서와 PR에 포함하지 않았습니다.

## 실행 결과

| 항목 | 결과 | 근거와 범위 |
|---|---|---|
| 추가 서비스 자동 테스트 | PASS — 138개 | `canarytrace`에서 `python -X utf8 -m pytest -q`. 등록·인증·권한·ZIP·문서·해시·비콘·CIDR·상관 분석·장치 인증·저장·비밀번호 복구·합성 에이전트 테스트 |
| 기존 루트 서버 회귀 테스트 | PASS — 48개 | 저장소 루트에서 `python -X utf8 -m pytest -q tests`. 원래 `app` 코드는 변경하지 않음. AI/Slack 연동은 테스트에서 모의 처리하며 외부 AI API 호출 없음 |
| 실제 로컬 HTTPS 통합 | PASS — 6개 검사 | 별도 프로세스·임시 DB·검증된 테스트 인증서로 아래 스모크 테스트 실행 |
| PowerShell 구문 | PASS | 추가된 전체 `.ps1`을 Windows PowerShell Parser로 검사 |
| 소스 에이전트 ZIP 빌드 | PASS | ZIP CRC, 패키지 manifest SHA-256, 포함된 모든 `.ps1`의 UTF-8 BOM 확인 |
| 한글 보존 | PASS | 실제 PowerShell stdout/stderr의 한글 JSON·오류, 4663 XML의 계정/경로, ZIP 한글 파일명·TXT 내용, DOCX 한글 내용 및 기존 `맑은 고딕`/동아시아 글꼴 메타데이터 |
| PR 파일 범위·인코딩 | PASS | 추가 파일 UTF-8 확인, PowerShell UTF-8 BOM 확인. 프론트엔드·실행 산출물·비밀정보 제외 |

추가 서비스 테스트에서 Starlette TestClient의 `httpx` 사용에 대한 사용 중단 예정 경고 1건이 발생했습니다. 테스트 실패는 없었습니다. 이는 실제 HTTPS 스모크 테스트 결과와 별개입니다.

## 실제 HTTPS 통합 재실행

`canarytrace` 디렉터리에서:

```powershell
$env:PYTHONUTF8 = '1'
.\.venv\Scripts\python.exe scripts\smoke_test.py
```

스크립트는 비어 있는 로컬 포트와 `artifacts/smoke-<ID>/`의 별도 구성·인증서·DB를 사용하고 종료 시 자신이 시작한 서버만 종료합니다. 운영 서버에 접속하거나 Windows 감사/방화벽 설정을 바꾸지 않습니다. 검사 항목은 다음과 같습니다.

1. 인증서를 검증한 실제 loopback HTTPS 연결
2. 인증 없는 ZIP 다운로드 거부
3. 인증된 ZIP 다운로드 및 ZIP/멤버 SHA-256 검증
4. DOCX 원격 이미지 URL에 대한 실제 HTTP 요청 및 SSE 갱신 수신
5. 실제 에이전트 전송 코드가 서명한 **합성 이벤트**의 HTTPS 전송, 서버 저장 및 공통 ID 연결
6. 서버 프로세스를 재시작한 뒤 이벤트 보존과 DB 레코드 무결성 확인

합성 장치 이름은 `SYNTHETIC-TRANSPORT-TEST`로 지정하며 격리된 DB에만 저장합니다. 스모크 테스트가 Windows Security 로그에서 실제 열람 기록을 수집했다고 해석하면 안 됩니다. Word가 자동으로 비콘을 요청했음을 검증한 것도 아닙니다.

## 이번 PR에서 검증하지 않은 항목

| 항목 | 결과 | 이유 |
|---|---|---|
| 실제 PC-B 설치·감사·파일 열람 | SKIP | 승인된 상대 물리 PC 연결이 없음 |
| 물리 USB 연결·복사·PC 간 이동 | SKIP | 해당 장비 시나리오 미실행. 자동 테스트는 합성 볼륨/복사 관측 |
| 실제 사내 SMTP 감사 로그 연동 | SKIP | 실제 게이트웨이 로그/접속 없음. 합성 로그 상관 분석만 검사 |
| Word 자동 외부 이미지 로드 | SKIP | 뷰어 보안 정책 및 실제 Word 열람 검증 없음. 문서 구조와 직접 HTTP 요청만 확인 |
| 프론트엔드 렌더링·대시보드 통합 | SKIP | 요청에 따라 프론트엔드 제외. SSE와 권한별 조회 API만 검증 |
| 서명된 MSI/EXE 설치 | SKIP | 결과물은 검토 가능한 Python/PowerShell 소스 설치 ZIP |

기존 서버와 새 서비스는 별도 실행 단위이며, 기존 프론트엔드의 요청을 새 서버로 자동 전환하거나 DB를 마이그레이션하지 않습니다. ZIP·로그·JUnit XML·개인 키는 `.gitignore` 대상이며 PR에 올리지 않습니다.
