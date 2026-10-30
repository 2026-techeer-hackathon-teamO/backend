"""Opt-in Windows Security 4663 collector. Run only on approved managed endpoints."""
import argparse
import hashlib
import json
import logging
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import httpx
from backend.security import event_signature
from .windows_info import local_ip, storage_info, file_identity
from .observations import ObservationMixin

LOG = logging.getLogger('dataguard.agent')
NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
HERE = Path(__file__).resolve().parent


def parse_4663(xml: str):
    # Windows 보안 감사 공급자가 생성한 파일 읽기/쓰기만 해석합니다. 파일 변경 감시를 열람으로 대체하지 않습니다.
    root = ET.fromstring(xml)
    if root.findtext('e:System/e:EventID', namespaces=NS) != '4663':
        return None
    provider = root.find('e:System/e:Provider', NS)
    if provider is None or provider.attrib.get('Name') != 'Microsoft-Windows-Security-Auditing':
        return None
    data = {el.attrib['Name']: el.text or '' for el in root.findall('e:EventData/e:Data', NS)}
    if data.get('ObjectType') != 'File':
        return None
    mask = int(data.get('AccessMask', '0'), 0)
    if not mask & 3:
        return None
    return {'record_id': int(root.findtext('e:System/e:EventRecordID', namespaces=NS)),
            'occurred_at': root.find('e:System/e:TimeCreated', NS).attrib['SystemTime'],
            'pc_name': root.findtext('e:System/e:Computer', namespaces=NS) or socket.gethostname(),
            'windows_user': data.get('SubjectDomainName', '') + '\\' + data.get('SubjectUserName', ''),
            'windows_sid': data.get('SubjectUserSid', 'UNKNOWN'),
            'process': data.get('ProcessName', ''), 'process_id': data.get('ProcessId', ''),
            'object_path': data.get('ObjectName', ''), 'access_mask': mask,
            'source_type': 'WINDOWS_SECURITY_4663'}


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def powershell(args):
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', *args], capture_output=True, encoding='utf-8', errors='replace', creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.lstrip('\ufeff').strip()


class Agent(ObservationMixin):
    def __init__(self, config_path):
        self.config_path = Path(config_path).resolve()
        self.cfg = json.loads(self.config_path.read_text('utf-8-sig'))
        if urlparse(self.cfg['server']).scheme != 'https':
            raise ValueError('TLS is mandatory for device authentication')
        if not self.cfg.get('roots'):
            raise ValueError('Explicit approved monitoring roots are required')
        self.roots = [Path(p).resolve() for p in self.cfg['roots']]
        ca = self.cfg.get('ca_cert')
        tls = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        self.client = httpx.Client(base_url=self.cfg['server'], headers={'X-Device-Key': self.cfg['device_key'], 'User-Agent': 'DataGuard-Windows-Agent/1.0'}, verify=tls, timeout=20, trust_env=False)
        self.db = sqlite3.connect(self.config_path.with_suffix('.spool.db'))
        self.db.execute('CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, path TEXT, payload TEXT)')
        self.db.commit()
        cached = json.loads(self.state('manifest', '{"files":[]}'))
        self.manifest = {sha: f for f in cached['files'] for sha in f['hashes']}
        self.issuances = {i['file_hash']: i for i in cached.get('issuances', [])}
        self.distributions = {d['sha256']: d for d in cached.get('distributions', [])}
        self.last_observations = 0
        self.identities = json.loads(self.state('identities', '{}'))
        self.last_diagnostic = {}
        self.last_manifest = 0
        self.last_delivery = []

    def state(self, key, default=None):
        row = self.db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
        return row[0] if row else default

    def set_state(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)', (key, str(value)))

    def refresh(self):
        # 드라이브 문자가 재사용되어도 오래된 USB 식별자가 남지 않도록 정책 갱신 때 캐시를 비웁니다.
        storage_info.cache_clear()
        response = self.client.get('/api/agent/manifest')
        response.raise_for_status()
        manifest = response.json()
        self.manifest = {sha: f for f in manifest['files'] for sha in f['hashes']}
        self.issuances = {i['file_hash']: i for i in manifest.get('issuances', [])}
        self.distributions = {d['sha256']: d for d in manifest.get('distributions', [])}
        self.set_state('manifest', json.dumps(manifest))
        self.db.commit()
        self.last_manifest = time.monotonic()

    def prime(self):
        """Snapshot file IDs, not access evidence. No read event is fabricated."""
        for root in self.roots:
            paths = [root] if root.is_file() else root.rglob('*')
            for path in paths:
                try:
                    if not path.is_file() or not self.approved_path(path) or path.stat().st_size > 10 * 1024 * 1024:
                        continue
                    sha = sha256(path)
                    if sha in self.manifest:
                        self.identities[file_identity(path)] = {'sha': sha, 'file_id': self.manifest[sha]['file_id'], 'path': str(path)}
                except OSError:
                    continue
        self.set_state('identities', json.dumps(self.identities))
        self.db.commit()

    def diagnostic(self, code, detail):
        LOG.error('%s %s', code, detail)
        if time.monotonic() - self.last_diagnostic.get(code, -1000) < 60:
            return
        self.last_diagnostic[code] = time.monotonic()
        key = str(uuid.uuid4())
        self.enqueue('/api/agent/diagnostics', {'external_id': key, 'code': code, 'detail': detail[:2000], 'occurred_at': datetime.now(timezone.utc).isoformat()}, 'diagnostic:' + key)
        self.db.commit()

    def approved_path(self, path):
        resolved = Path(path).resolve()
        return any(resolved.is_relative_to(root) for root in self.roots)

    def prepare(self, xml):
        # 승인된 폴더에서만 파일 식별을 수행하고 에이전트 자신의 해시 계산은 재수집하지 않습니다.
        event = parse_4663(xml)
        if not event or not self.approved_path(event['object_path']):
            return None
        try:
            if int(event['process_id'], 0) == os.getpid():
                return None  # Hashing the file must not recursively generate telemetry.
        except ValueError:
            return None
        path = Path(event['object_path'])
        if path.is_dir():
            return None  # Windows는 디렉터리도 File 객체로 기록하므로 문서 수집 대상에서 제외합니다.
        if not path.is_file():
            self.diagnostic('UNRESOLVED_ACCESS', f"record={event['record_id']}; file_missing; identity cannot be resolved")
            return None
        before = path.stat()
        if before.st_size > 10 * 1024 * 1024:
            return None
        sha = sha256(path)
        after = path.stat()
        if (before.st_mtime_ns, before.st_size) != (after.st_mtime_ns, after.st_size):
            self.diagnostic('UNRESOLVED_ACCESS', f"record={event['record_id']}; file_changed_during_hash")
            return None
        identity = file_identity(path)
        previous = self.identities.get(identity)
        match = self.manifest.get(sha)
        if not match and event['access_mask'] & 2 and previous and previous['sha'] in self.manifest:
            # 내용이 달라졌더라도 이전 파일 ID와 실제 쓰기 감사가 함께 있어야 계보를 생성합니다.
            lineage = {'file_id': previous['file_id'], 'previous_hash': previous['sha'], 'new_hash': sha, 'record_id': event['record_id'], 'occurred_at': event['occurred_at'], 'object_path': str(path), 'file_identity': identity, 'evidence_type': 'OBSERVED_4663_WRITE_SAME_FILE_ID'}
            self.enqueue('/api/agent/lineage', lineage, f"lineage:{event['record_id']}:{sha}")
            match = self.manifest[previous['sha']]
            self.manifest[sha] = match
        elif not match and previous:
            self.diagnostic('UNRESOLVED_ACCESS', f"record={event['record_id']}; changed content without observed write; lineage not inferred")
        if not match:
            return None  # No normal-file content, name or user is sent to the server.
        if previous and previous.get('path') and previous['path'] != str(path) and previous['sha'] == sha:
            self.observe('FILE_RENAMED' if Path(previous['path']).parent == path.parent else 'FILE_MOVED', 'STABLE_FILE_ID_SNAPSHOT', actor=False, file_id=match['file_id'], sha256=sha, object_path=str(path), previous_path=previous['path'], file_identity=identity, **storage_info(path.drive))
        self.identities[identity] = {'sha': sha, 'file_id': match['file_id'], 'path': str(path)}
        self.set_state('identities', json.dumps(self.identities))
        if event['access_mask'] & 2:
            self.observe('FILE_WRITE_OBSERVED', 'WINDOWS_SECURITY_4663', actor=False, external_id='write:' + str(event['record_id']) + ':' + event['occurred_at'], file_id=match['file_id'], sha256=sha, **{k: event[k] for k in ['record_id', 'occurred_at', 'pc_name', 'windows_user', 'windows_sid', 'process', 'process_id', 'object_path']}, **storage_info(path.drive))
        if not event['access_mask'] & 1:
            return None
        issuance = self.issuances.get(sha, {})
        return {**event, 'file_id': match['file_id'], 'sha256': sha, 'distribution_id': issuance.get('distribution_id'), 'issuance_id': issuance.get('issuance_id'), 'local_ip': local_ip(), 'detected_at': datetime.now(timezone.utc).isoformat(), **storage_info(path.drive)}

    def enqueue(self, path, payload, key):
        # 로컬 SQLite 전송함에 보관하여 네트워크 단절 후에도 같은 ID로 안전하게 재전송합니다.
        self.db.execute('INSERT OR IGNORE INTO pending VALUES (?,?,?)', (key, path, json.dumps(payload)))

    def flush(self):
        # 각 재전송마다 현재 시각으로 서명합니다. 서버가 영구 거절한 자료는 별도 테이블에 보존합니다.
        self.last_delivery = []
        for key, path, payload in self.db.execute('SELECT id,path,payload FROM pending ORDER BY rowid LIMIT 256').fetchall():
            stamp = str(int(time.time()))
            raw = payload.encode('utf-8')
            response = self.client.post(path, content=raw, headers={'Content-Type': 'application/json', 'X-Event-Timestamp': stamp, 'X-Event-Signature': event_signature(self.cfg['device_key'], stamp, path, raw)})
            if response.status_code in {403, 404, 409, 422}:
                self.db.execute('CREATE TABLE IF NOT EXISTS rejected (id TEXT PRIMARY KEY, path TEXT, payload TEXT, reason TEXT)')
                self.db.execute('INSERT OR REPLACE INTO rejected VALUES (?,?,?,?)', (key, path, payload, response.text))
                self.db.execute('DELETE FROM pending WHERE id=?', (key,))
                self.db.commit()
                self.diagnostic('DELIVERY_REJECTED', f'{key}: HTTP {response.status_code}; retained in local rejected table')
                continue
            response.raise_for_status()
            self.last_delivery.append(response.json())
            self.db.execute('DELETE FROM pending WHERE id=?', (key,))
            self.db.commit()
            LOG.info('DELIVERED %s %s', key, response.text)

    def poll(self):
        if not self.manifest or time.monotonic() - self.last_manifest > 30:
            try:
                self.refresh()
                if not self.identities:
                    self.prime()
            except httpx.HTTPError:
                cached = self.state('manifest')
                if not cached:
                    raise
                self.manifest = {sha: f for f in json.loads(cached)['files'] for sha in f['hashes']}
                LOG.warning('Using cached manifest; server unavailable. Pending events retained.')
        if time.monotonic() - self.last_observations > 10:
            self.last_observations = time.monotonic()
            try:
                if self.cfg.get('monitor_usb_devices', True): self.monitor_volumes()
                self.monitor_paths()
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                self.diagnostic('COLLECTION_FAILED', 'Device/path observation failed: ' + type(exc).__name__)
        last = self.state('checkpoint')
        output = powershell(['-File', str(HERE / 'read_security.ps1'), '-AfterRecord', str(last or -1)])
        batch = json.loads(output)
        if batch.get('reset'):
            self.diagnostic('AUDIT_LOG_RESET', 'Old checkpoint exceeds current record ID; coverage gap')
        if batch.get('gap'):
            self.diagnostic('AUDIT_LOG_GAP', 'Older records were overwritten before collection')
        prepared = []
        for entry in batch['events']:
            try:
                payload = self.prepare(entry['xml'])
                if payload:
                    prepared.append(payload)
                    self.enqueue('/api/agent/events', payload, f"4663:{payload['record_id']}:{payload['occurred_at']}")
            except (OSError, ValueError, ET.ParseError) as exc:
                self.diagnostic('UNRESOLVED_ACCESS', f"record={entry.get('record_id')} reason={type(exc).__name__}")
        self.set_state('checkpoint', batch['checkpoint'])
        self.db.commit()  # Durable outbox and checkpoint advance atomically.
        self.flush()
        return prepared

    def copy_usb(self, source, destination):
        # USB 버스 확인과 복사 전후 해시 검증을 모두 통과해야 복사 관측 기록을 전송합니다.
        self.refresh()
        source, destination = Path(source).resolve(), Path(destination).resolve()
        if not self.approved_path(source):
            raise ValueError('Source is outside approved monitoring roots')
        sha = sha256(source)
        match = self.manifest.get(sha)
        distribution = self.distributions.get(sha)
        if not match and not distribution:
            raise ValueError('Source is not a registered confidential file')
        if destination.exists():
            raise ValueError('Destination already exists; refusing overwrite')
        if os.name != 'nt':
            raise ValueError('Windows removable-drive verification required')
        # Drive letter is a validated two-character identifier, never arbitrary script text.
        drive = destination.drive.upper()
        if len(drive) != 2 or drive[0] not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' or drive[1] != ':':
            raise ValueError('Local removable drive required')
        storage_info.cache_clear()
        info = storage_info(drive)
        if info['storage_type'] != 'USB':
            raise ValueError('USB bus could not be verified; no USB copy claim made')
        identity = {'file_id': match['file_id']} if match else {'distribution_id': distribution['distribution_id']}
        self.observe('COPY_ATTEMPT', 'APPROVED_COPY_TOOL', sha256=sha, object_path=str(destination), previous_path=str(source), **identity, **info)
        self.db.commit()
        try:
            with source.open('rb') as src, destination.open('xb') as dst:
                shutil.copyfileobj(src, dst)
                dst.flush(); os.fsync(dst.fileno())
            if sha256(destination) != sha or sha256(source) != sha:
                raise ValueError('Copy hash mismatch; no movement evidence submitted')
        except (OSError, ValueError):
            self.observe('COPY_FAILED', 'APPROVED_COPY_TOOL', sha256=sha, object_path=str(destination), **identity, **info)
            self.db.commit()
            raise
        self.observe('FILE_WRITE_COMPLETED', 'APPROVED_COPY_TOOL', sha256=sha, object_path=str(destination), **identity, **info)
        external = str(uuid.uuid4())
        body = {**identity, 'sha256': sha, 'external_id': external, 'occurred_at': datetime.now(timezone.utc).isoformat(), 'channel': 'USB', 'stage': 'FILE_COPIED_TO_USB', 'source': str(source), 'destination': str(destination), 'evidence_type': 'APPROVED_COPY_TOOL', 'evidence_reference': f"volume={info['volume_id']};copy={external}", 'volume_id': info['volume_id'], 'usb_device_id': info['usb_device_id'], 'copy_observed': True}
        self.enqueue('/api/integrations/movements', body, 'copy:' + external)
        self.db.commit()
        self.flush()
        return body

    def close(self):
        self.client.close()
        self.db.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--copy', nargs=2, metavar=('SOURCE', 'DESTINATION'))
    parser.add_argument('--extract', nargs=2, metavar=('ZIP', 'DESTINATION'))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s', handlers=[logging.StreamHandler(), logging.FileHandler(Path(args.config).with_suffix('.log'), encoding='utf-8')])
    agent = Agent(args.config)
    try:
        if args.extract:
            print(json.dumps(agent.extract_zip(*args.extract), ensure_ascii=False)); return
        if args.copy:
            print(json.dumps(agent.copy_usb(*args.copy), ensure_ascii=False))
            return
        while True:
            try:
                found = agent.poll()
                LOG.info('POLL matched=%d pending=%d', len(found), agent.db.execute('SELECT COUNT(*) FROM pending').fetchone()[0])
            except Exception:
                LOG.exception('Collection or delivery failed; no success claimed')
                agent.diagnostic('COLLECTION_FAILED', 'Security log collection or delivery failed. See local agent log for details; no coverage claimed.')
                try:
                    agent.flush()
                except httpx.HTTPError:
                    pass
                if args.once:
                    raise
            if args.once:
                break
            time.sleep(2)
    finally:
        agent.close()


if __name__ == '__main__':
    main()
