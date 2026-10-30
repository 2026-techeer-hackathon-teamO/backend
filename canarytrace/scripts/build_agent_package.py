"""Build a reviewable source installer ZIP, not an untested native executable."""
import json
import hashlib
import zipfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
target = ROOT / 'artifacts/CanaryTrace-Windows-Agent.zip'
target.parent.mkdir(parents=True, exist_ok=True)
readme = '''# CanaryTrace Windows Agent
Requires Windows, Python 3.11+, HTTPS CA trust, unique enrolled device credentials and read permission on Security logs.
Installation requires explicit -AcceptCollectionNotice. No automatic service, hidden persistence, elevation or remote execution is installed.
Collects approved-root registered-file reads/writes, process, Windows account/SID, path, timestamps, and USB volume identifiers.
Only audited 4663 ReadData is a file read. File rename/move snapshots are CORRELATED. Arbitrary OS copy attempts/completion are not guaranteed.
USB copy lifecycle is observed by --copy; registered ZIP extraction is observed by --extract. Plain Explorer extraction remains UNKNOWN.

After extracting this package, run:
  .\\Install-Agent.ps1 -Destination C:\\CanaryTrace-Agent -AcceptCollectionNotice
Then enroll in the destination folder (administrator credentials are prompted, not saved):
  .\\.venv\\Scripts\\python.exe -m scripts.enroll_agent --server https://YOUR-APPROVED-SERVER:8443 --ca C:\\Approved\\ca.pem --name PC-B --root C:\\ApprovedDocuments --out C:\\CanaryTrace-Agent\\device.json
Use the supplied enable_file_audit.ps1 ONLY on an approved NTFS folder, from an administrator console, retaining its policy/SACL backup.
Start visibly: .\\Start-Agent.ps1 -Config C:\\CanaryTrace-Agent\\device.json
Ctrl+C stops. The administrator dashboard can revoke the device.
Uninstall dry run: .\\Uninstall-Agent.ps1
Remove after review: .\\Uninstall-Agent.ps1 -RemoveLocalFiles
Restore audit backups only if no intervening organization policy changes occurred.
Do not share device.json. Do not disable TLS or Word Protected View. A network request never proves human reading.
This is a source/PowerShell installer requiring a Python runtime, not a signed MSI/EXE or kernel DLP driver.
'''
members = {}
for p in (ROOT / 'agent').glob('*.py'): members['agent/' + p.name] = p.read_bytes()
members['agent/read_security.ps1'] = (ROOT / 'agent/read_security.ps1').read_bytes()
for name in ['__init__.py', 'security.py', 'archives.py']: members['backend/' + name] = (ROOT / 'backend' / name).read_bytes()
for name in ['enroll_agent.py', 'enable_file_audit.ps1', 'restore_file_audit.ps1', 'import_email_audit.py']: members['scripts/' + name] = (ROOT / 'scripts' / name).read_bytes()
for p in (ROOT / 'scripts/agent').glob('*.ps1'): members[p.name] = p.read_bytes()
members['requirements-agent.txt'] = b'fastapi==0.162.0\nhttpx==0.28.1\n'
members['README-AGENT.md'] = readme.encode()
members['package-manifest.json'] = json.dumps({n: hashlib.sha256(b).hexdigest() for n,b in members.items()}, indent=2).encode()
with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as z:
    for name, raw in members.items(): z.writestr(name, raw)
with zipfile.ZipFile(target) as z:
    assert z.testzip() is None and not any(n.endswith('device.json') or n.startswith('.runtime') for n in z.namelist())
print(target)
