import argparse
import getpass
import json
import os
import ssl
import subprocess
from pathlib import Path
import httpx

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--server', default='https://localhost:8443')
    p.add_argument('--ca', required=True)
    p.add_argument('--name', required=True)
    p.add_argument('--kind', choices=['WINDOWS_AGENT', 'SMTP_GATEWAY'], default='WINDOWS_AGENT')
    p.add_argument('--root', action='append', required=True)
    p.add_argument('--out', required=True)
    a = p.parse_args()
    out = Path(a.out).resolve()
    if out.exists():
        raise SystemExit('Refusing to overwrite existing device credentials')
    with httpx.Client(base_url=a.server, verify=ssl.create_default_context(cafile=a.ca), trust_env=False) as c:
        r = c.post('/api/login', json={'username': 'admin', 'password': getpass.getpass('Administrator password: ')})
        r.raise_for_status()
        headers = {'Authorization': 'Bearer ' + r.json()['access_token']}
        r = c.post('/api/devices', json={'name': a.name, 'kind': a.kind}, headers=headers)
        r.raise_for_status()
        device = r.json()
        c.post('/api/logout', headers=headers).raise_for_status()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({'server': a.server, 'device_id': device['id'], 'device_key': device['device_key'], 'ca_cert': str(Path(a.ca).resolve()), 'roots': [str(Path(r).resolve()) for r in a.root]}, indent=2), 'utf-8')
    if os.name == 'nt':
        from agent.windows_info import current_user
        identity = current_user()['windows_user']
        subprocess.run(['icacls.exe', str(out), '/inheritance:r', '/grant:r', f'{identity}:(F)', '*S-1-5-18:(F)'], check=True, capture_output=True)
    print('Device enrolled. Secret saved with restricted file ACL:', out)

if __name__ == '__main__':
    main()
