"""Build a public LAN onboarding kit without admin/device/TLS private keys."""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

ROOT=Path(__file__).resolve().parents[1]


def main():
    p=argparse.ArgumentParser(); p.add_argument('--stage', type=Path, required=True); p.add_argument('--agent-package', type=Path, required=True, help='Source installer built from the agent repository'); a=p.parse_args()
    stage=a.stage.resolve()
    if not stage.is_relative_to((ROOT/'.runtime/lan-setup').resolve()): raise ValueError('Invalid stage')
    plan=json.loads((stage/'plan.json').read_text('utf-8'))
    cfg=json.loads((ROOT/'.runtime/settings.json').read_text('utf-8'))
    assert cfg['public_base_url']==plan['url'], 'LAN plan not active'
    latest=json.loads((ROOT/'artifacts/distributions/latest.json').read_text('utf-8'))
    distribution=json.loads((Path(latest['output'])/'distribution.json').read_text('utf-8'))
    cert=x509.load_pem_x509_certificate((ROOT/'.runtime/tls/cert.pem').read_bytes())
    assert cert.fingerprint(hashes.SHA256()).hex()==plan['certificate_sha256']
    files={}
    with zipfile.ZipFile(a.agent_package) as z:
        assert z.testzip() is None
        for name in z.namelist(): files['agent-package/'+name]=z.read(name)
    files['ccc-canary-distribution.zip']=Path(latest['zip_path']).read_bytes()
    files['server-cert.pem']=cert.public_bytes(serialization.Encoding.PEM)
    files['server-cert.cer']=cert.public_bytes(serialization.Encoding.DER)
    for name in ['Setup-PC-B.ps1','Check-Connection.py']: files[name]=(ROOT/'scripts'/name).read_bytes()
    connection={'server':cfg['public_base_url'],'certificate_sha256':plan['certificate_sha256'],'certificate_valid_until':plan['valid_until'],'distribution_id':latest['distribution_id'],'distribution_sha256':hashlib.sha256(files['ccc-canary-distribution.zip']).hexdigest()}
    files['connection.json']=json.dumps(connection,indent=2).encode()
    files['README-PC-B.md']=f'''# 같은 Wi-Fi 관리 PC 설치

서버: {cfg['public_base_url']}
배포 ID: {latest['distribution_id']}
인증서 SHA-256: {plan['certificate_sha256']}
만료: {plan['valid_until']}

이 ZIP을 승인된 상대 PC에 전달하여 전체 압축을 해제하세요. 개인키·장치키·관리자 암호는 포함하지 않습니다. Python 3.11+와 의존성 설치용 인터넷이 필요합니다. 같은 Wi-Fi라도 게스트/AP 격리 정책에 따라 연결되지 않을 수 있습니다.

먼저 대상 PC에서 `python .\\Check-Connection.py`를 실행하면 지정 인증서로 HTTPS를 검증합니다. 운영체제 인증서 검증을 해제하지 않습니다.

기업 관리자가 관리자 PowerShell에서 압축을 푼 폴더로 이동한 뒤:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Setup-PC-B.ps1 -AcceptCollectionNotice -TrustTestCertificate
```

기본 설치 위치는 C:\\CanaryTrace-Agent, 감사 폴더는 C:\\ApprovedCanaryDocuments입니다. 기존 설치 폴더를 덮어쓰지 않습니다. 설치 도중 중앙 서버의 admin 암호를 권한 있는 관리자가 직접 입력해야 합니다. 상대 사용자에게 관리자 암호를 전달하지 마세요. 설치 프로그램은 PC마다 새로운 장치 키를 발급하고 로컬 파일 ACL을 제한합니다.

수집 범위: 승인 폴더에 있는 등록 문서의 읽기/쓰기, Windows 사용자/SID, PC/장치, 프로세스/경로/시각, USB 장치 연결 목록. 지정한 NTFS 폴더의 SACL과 파일 시스템 성공 감사를 설정하며 기존 정책을 audit-backup에 보관합니다. 다른 폴더 전체를 감시하지 않습니다. --TrustTestCertificate는 이번 30일 시험 인증서를 현재 Windows 사용자 신뢰 저장소에 명시적으로 추가합니다. Word 외부 이미지나 보호된 보기 설정은 변경하지 않습니다. 다른 Windows 사용자로 Word를 실행한다면 해당 사용자 인증서 신뢰는 별도 관리해야 합니다.

설치 후 ZIP을 검증하여 감사 폴더 안에 추출하고 전경 에이전트를 실행합니다. 콘솔을 유지한 채 받은 DOCX/TXT를 여세요. 관리자 PC의 ZIP 배포 추적 화면에서 위 배포 ID와 접근한 PC 이름을 확인합니다. 에이전트 종료는 Ctrl+C. 문서 비콘 요청은 실제 사람의 열람 증거가 아닙니다. 에이전트 파일 감사는 Word 자동 이미지가 차단되어도 작동할 수 있습니다.

제거: 에이전트 중지 → 관리자 대시보드에서 해당 장치 폐기 → 조직 정책 변경 여부 검토 후 scripts/restore_file_audit.ps1로 승인 백업 복원 → Uninstall-Agent.ps1 -RemoveLocalFiles. 추가한 시험 인증서는 certmgr.msc의 현재 사용자/신뢰할 수 있는 루트에서 connection.json의 지문과 installation의 test-certificate-trust.json을 비교하여 해당 인증서만 제거하세요. 데이터/감사 백업은 제거 전에 검토하세요.

이 패키지는 상대 PC에서 아직 실행되지 않았습니다. 관리자 PC의 로컬 HTTPS 시험은 상대 PC의 Wi-Fi 연결 시험을 대신하지 않습니다. 현재 IP가 DHCP로 변경되면 서버 주소·인증서를 다시 구성하고 새 ZIP/설치 패키지를 발급해야 합니다.
'''.encode('utf-8')
    files['kit-manifest.json']=json.dumps({name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()},indent=2).encode()
    out=ROOT/'artifacts/lan'/latest['distribution_id']; out.mkdir(parents=True,exist_ok=False)
    kit=out/'CanaryTrace-PC-B-LAN.zip'
    with zipfile.ZipFile(kit,'w',zipfile.ZIP_DEFLATED) as z:
        for name,raw in files.items(): z.writestr(name,raw)
    with zipfile.ZipFile(kit) as z:
        assert z.testzip() is None
        assert not any(n.endswith(('key.pem','device.json','.env')) for n in z.namelist())
        assert not any(b'PRIVATE KEY-----' in raw for raw in files.values())
    info={**connection,'kit':str(kit),'zip_path':latest['zip_path'],'output':str(out),'stage':str(stage),'status':'READY_FOR_APPROVED_PC_INSTALLATION','remote_installation':'NOT_PERFORMED'}
    (out/'lan-package.json').write_text(json.dumps(info,indent=2),'utf-8')
    (ROOT/'artifacts/lan/latest.json').write_text(json.dumps(info,indent=2),'utf-8')
    print(json.dumps(info,indent=2))


if __name__=='__main__':main()
