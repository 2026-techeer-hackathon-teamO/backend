"""Restart the actual local service and verify persisted distribution/event IDs and ZIP."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.ccc_distribution import api_client


def main():
    latest = json.loads((ROOT / 'artifacts/distributions/latest.json').read_text('utf-8'))
    identifier, out = latest['distribution_id'], Path(latest['output'])
    with api_client() as c:
        response = c.get('/api/distributions/' + identifier); response.raise_for_status()
        before = response.json()
    for script in ['stop.ps1', 'start_backend.ps1']:
        subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(ROOT / 'scripts' / script)], cwd=ROOT, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    with api_client() as c:
        response = c.get('/api/distributions/' + identifier); response.raise_for_status()
        after = response.json()
        download = c.get('/api/distributions/' + identifier + '/download'); download.raise_for_status()
        checks = {
            'distribution_id_preserved': before['id'] == after['id'],
            'issuance_ids_preserved': {f['issuance_id'] for f in before['files']} == {f['issuance_id'] for f in after['files']},
            'event_ids_preserved': {e['event_id'] for e in before['events']}.issubset({e['event_id'] for e in after['events']}),
            'download_records_preserved': {d['id'] for d in before['downloads']}.issubset({d['id'] for d in after['downloads']}),
            'zip_unchanged': hashlib.sha256(download.content).hexdigest() == before['sha256'],
            'database_integrity': c.get('/api/integrity').json()['ok'],
            'endpoint_observations_preserved': {o['id'] for o in before.get('observations', [])}.issubset({o['id'] for o in after.get('observations', [])}),
        }
    result = {'distribution_id': identifier, 'status': 'PASS' if all(checks.values()) else 'FAIL', 'checks': checks, 'before_event_count': len(before['events']), 'after_event_count': len(after['events'])}
    (out / 'restart-results.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if all(checks.values()) else 1)


if __name__ == '__main__':
    main()
