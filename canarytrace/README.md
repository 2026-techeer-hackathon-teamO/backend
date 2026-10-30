# CanaryTrace — ZIP 배포 및 관리 장치 접근 추적

승인된 테스트 문서의 ZIP 배포본을 만들고, 문서 비콘 요청과 인증된 Windows 장치의 파일 접근 보고를 배포 ID로 연결하는 추가 서비스입니다. 프론트엔드는 포함하지 않습니다. API 명세는 [docs/API.md](docs/API.md), 검증 기록은 [docs/VALIDATION.md](docs/VALIDATION.md)에 있습니다.

## 기존 서버와의 관계

팀이 작업한 저장소 루트의 `app`, API, DB 및 기존 실행 명령을 변경하지 않기 위해 `canarytrace/`에 독립 실행 단위로 추가했습니다. **아래 명령은 모두 `canarytrace` 디렉터리에서 실행합니다.** 기존 서버와 새 서버는 인증 방식과 쓰기 요청 스키마가 다르며 DB를 자동으로 이관하지 않습니다. 기존 프론트엔드의 API 호환성을 보장하거나 UI 연동을 완료했다는 의미가 아닙니다.

새 구현은 외부 OpenAI·Claude·Gemini·Grok API를 호출하지 않습니다. 루트 서버에 이미 존재하는 AI 연동 코드는 수정하지 않습니다.

## 구현 범위와 관측 한계

- Windows Known Folder API로 실제 Desktop 및 `ccc`, `ccc.*` 후보를 찾고 원본 fingerprint·형식·해시를 검사합니다. 원본은 수정하지 않습니다. 여러 후보는 관리자가 선택합니다.
- DOCX·PDF·UTF-8 TXT의 승인된 사본에 고유 토큰을 연결합니다. ZIP, manifest, 원본/배포 사본 해시, distribution/file/decoy/issuance/token ID를 저장합니다. 경로 탈출·링크·암호화/지원하지 않는 문서와 크기 제한을 검사합니다.
- DOCX 원격 이미지는 명시적으로 활성화한 경우만 추가합니다. Word의 보호된 보기·외부 콘텐츠 정책을 우회하지 않습니다. PDF/TXT는 명시적 확인 링크이며, 열기만 하면 네트워크 요청이 발생한다고 주장하지 않습니다.
- 장치 키와 요청 HMAC으로 수신자를 인증하고, 중복 이벤트를 방지합니다. Windows 4663 ReadData 보고에 PC·계정/SID·프로세스·경로가 포함됩니다. 이는 인증된 장치의 보고이며 사람이 내용을 읽었다는 증명은 아닙니다.
- USB 연결/분리는 볼륨 목록 비교, 이름/위치 변경은 파일 식별자 비교로 관측합니다. 임의의 Explorer 복사·압축 해제를 전부 감지하지 않습니다. 승인된 `--copy`/`--extract` 도구의 동작에 한해 복사/추출 단계가 기록됩니다.
- SMTP 감사 JSONL 입력과 USB 이동을 공통 ID·해시·시각으로 상관 분석합니다. 이메일을 보내거나 실제 메일 수신함을 자동으로 조사하지 않습니다. 증거가 없으면 `UNKNOWN`이며 해시 일치만으로 경로를 확정하지 않습니다.
- 내부/외부 CIDR 판정, 스캐너 의심 표시, 역할별 개인정보 필터, 보관 정책, 감사 레코드 HMAC, SQLite 영속 저장, SSE 갱신 API를 제공합니다. 비콘에는 서버 관측 IP/시각/User-Agent만 있으며 PC·사용자 이름은 없습니다.

## 서버 실행 — Windows PowerShell

Python 3.11 이상을 준비합니다. 저장소 루트에서:

```powershell
Set-Location .\canarytrace
$env:PYTHONUTF8 = '1'
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe scripts\setup.py
.\.venv\Scripts\python.exe -m backend.run
```

기본 주소는 `https://localhost:8443/docs`입니다. `setup.py`는 로컬 `.env`에 임의 관리자 암호와 무결성 키를 생성합니다. 관리자 계정은 `admin`입니다. 빈 `.env.example`을 `.env`로 복사할 필요가 없습니다. TLS 인증서는 테스트용이며 `.runtime/tls/cert.pem`으로 검증합니다. 운영에서는 조직이 승인한 인증서를 사용합니다.

서버 실행 후 다른 PowerShell에서:

```powershell
Set-Location .\canarytrace
$env:PYTHONUTF8 = '1'
.\.venv\Scripts\python.exe scripts\health.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\smoke_test.py
```

백그라운드 서버가 필요한 경우 `scripts/start_backend.ps1 -Install`, 종료는 `scripts/stop.ps1`을 사용합니다. 이 시작 스크립트는 서버만 실행합니다. 에이전트는 승인된 장치에서 별도로 실행합니다. 관리자 암호 복구는 서버를 중지한 후 `scripts/reset_admin_password.py --generate`로 실행하고 서버를 재시작합니다. 기존 세션은 폐기됩니다.

## ccc 검사 및 새 ZIP 발급

```powershell
.\.venv\Scripts\python.exe scripts\ccc_distribution.py --inspect-only
# 원본이 기밀이거나 테스트 데이터인지 불명확하면 가상 문서로 별도 배포본 생성
.\.venv\Scripts\python.exe scripts\ccc_distribution.py --synthetic --docx-remote-image
# 검사한 실제 테스트 문서만 승인하여 사용할 경우
.\.venv\Scripts\python.exe scripts\ccc_distribution.py --source 'C:\ApprovedTestData\ccc' --approved-test-files --docx-remote-image
```

위 `--source` 경로는 예시이며 실제로 확인한 경로로 바꾸어야 합니다. 결과는 `artifacts/distributions/<실행별 ID>/`에 저장되고 `latest.json`에 실제 경로가 기록됩니다. ZIP 다운로드에는 인증과 권한이 필요합니다. 다운로드 기록만으로 압축 해제·파일 열람을 확정하지 않습니다.

## 관리 대상 PC의 에이전트 설치와 실행

관리자 PC에서 소스 설치 ZIP을 생성합니다.

```powershell
.\.venv\Scripts\python.exe scripts\build_agent_package.py
```

결과는 `artifacts/CanaryTrace-Windows-Agent.zip`입니다. 승인된 PC에서 압축 해제하고 포함된 `README-AGENT.md`의 수집 고지를 확인합니다. 서명된 MSI/EXE가 아닌 Python/PowerShell 설치 패키지입니다.

```powershell
# 압축 해제 폴더에서 실행. 기존 설치 경로는 덮어쓰지 않습니다.
.\Install-Agent.ps1 -Destination C:\CanaryTrace-Agent -AcceptCollectionNotice
Set-Location C:\CanaryTrace-Agent
$env:PYTHONUTF8 = '1'
# 실제 접근 가능한 HTTPS 주소와 검증한 공개 인증서 경로를 사용합니다.
.\.venv\Scripts\python.exe -m scripts.enroll_agent --server https://APPROVED-SERVER:8443 --ca C:\Approved\server-cert.pem --name PC-B --root C:\ApprovedDocuments --out C:\CanaryTrace-Agent\device.json
# 승인된 관리자 PowerShell에서 실행. 기존 감사 정책/SACL 백업을 보관합니다.
.\scripts\enable_file_audit.ps1 -Path C:\ApprovedDocuments -BackupDirectory C:\CanaryTrace-Agent\audit-backup
.\Start-Agent.ps1 -Config C:\CanaryTrace-Agent\device.json
```

등록 시 관리자가 암호를 직접 입력하며 PC마다 다른 장치 키를 발급합니다. `device.json`은 공유하지 않습니다. 에이전트에는 Security 로그 읽기 권한과 대상 NTFS 폴더의 성공 감사/SACL이 필요합니다. 계정의 권한을 자동 상승시키지 않습니다. 에이전트는 콘솔에서 실행하며 `Ctrl+C`로 종료합니다.

승인된 루트 안에서 등록된 ZIP을 추출하거나 USB로 복사하려면 에이전트를 중지한 후 같은 구성으로 실행합니다.

```powershell
.\.venv\Scripts\python.exe -m agent.windows_agent --config .\device.json --extract C:\ApprovedDocuments\ccc-canary-distribution.zip C:\ApprovedDocuments\Received
.\.venv\Scripts\python.exe -m agent.windows_agent --config .\device.json --copy C:\ApprovedDocuments\Received\test.txt E:\ApprovedDocuments\test.txt
```

실제 USB 드라이브와 승인된 루트로 경로를 바꾸어야 합니다. 기존 대상은 덮어쓰지 않습니다. 모니터링을 재개한 후 등록된 문서를 엽니다. `GET /api/events`, `/api/observations`, `/api/routes`, 배포본 상세 API에서 관측을 확인할 수 있습니다. 서버에서 `scripts/watch_remote_pc.py --seconds 60`을 실행하면 새로 수신되는 장치 파일 이벤트를 콘솔에 표시합니다. 새 이벤트를 합성하지 않습니다.

제거는 실행 중인 에이전트를 중지하고 서버에서 장치를 폐기한 후 수행합니다. 조직 감사 정책의 후속 변경 여부를 검토하여 `scripts/restore_file_audit.ps1`로 백업을 복원하고, `Uninstall-Agent.ps1`의 미리보기 후 `-RemoveLocalFiles`를 사용합니다.

## 같은 Wi-Fi 시연 및 이메일 감사 입력

서버의 현재 사설 IPv4 주소를 확인한 후 `scripts/prepare_lan.py --host <실제 IP>`로 변경 계획을 만듭니다. `scripts/Apply-Lan.ps1 -Stage <출력된 stage>`는 관리자 권한으로 실행하며, 해당 서브넷에 한정된 방화벽 규칙과 TLS 설정을 적용합니다. `-Restore`로 계획의 백업을 복원할 수 있습니다. 기존 인증서를 바꾸면 새 ZIP을 발급해야 합니다. Word의 인증서 신뢰 및 외부 리소스 허용 여부는 별도 정책입니다.

새 배포본과 에이전트 ZIP을 만든 후 `scripts/build_lan_kit.py --stage <적용된 stage> --agent-package .\artifacts\CanaryTrace-Windows-Agent.zip`으로 PC-B 설치 키트를 만들 수 있습니다. 공개 인증서만 포함하며 관리자 암호·장치 키·TLS 개인 키는 넣지 않습니다. 게스트 Wi-Fi 격리, 라우터 및 실제 PC-B 연결은 별도 검증 대상입니다.

승인된 SMTP 게이트웨이를 `--kind SMTP_GATEWAY`로 등록한 후 `python -m scripts.import_email_audit --config <게이트웨이 구성> --jsonl <승인된 감사 JSONL>`을 사용합니다. 행에는 `file_id`, `sha256`, `external_id`, `occurred_at`, `source`, `destination`, `evidence_reference`가 필요하며 `distribution_id`, `issuance_id`, `message_id`, `stage`, `recipient_device_id`를 함께 지정할 수 있습니다. 임의 시연 로그를 실제 메일 증거로 입력하지 마세요.

## 한글 인코딩과 비밀정보

문서·Python·JSON은 UTF-8을 사용하고 Windows PowerShell 5.1 스크립트는 UTF-8 BOM으로 저장합니다. `.editorconfig`에 같은 규칙을 명시했습니다. Python 실행은 `PYTHONUTF8=1` 또는 `python -X utf8`을 사용합니다. Windows 계정/경로를 조회하는 PowerShell 출력도 UTF-8로 지정하여 한글 계정, 파일 경로와 오류 메시지를 보존합니다. 터미널에서는 한글 글리프가 있는 맑은 고딕 등 설치된 글꼴을 사용하세요. 문서 원본의 글꼴은 변경하지 않습니다.

`.env`, `.runtime`, DB, 로그, 인증서/개인 키, `device.json`, 생성 ZIP 및 실제 사용자/장치 기록은 Git에 올리지 않습니다. `.env.example`은 빈 설정 템플릿입니다. 실제 PC-B·USB·이메일 장비 검증 결과와 합성 테스트 결과는 구분하여 기록해야 합니다.
