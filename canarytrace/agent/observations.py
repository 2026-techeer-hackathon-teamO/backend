"""Transparent observations within configured monitoring roots; no inferred reads."""
import hashlib
import json
import os
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .windows_info import usb_volumes, current_user, storage_info, file_identity


class ObservationMixin:
    def observe(self, event_type, method, *, external_id=None, actor=True, **details):
        key = external_id or str(uuid.uuid4())
        ids = self.issuances.get(details.get('sha256'), {}) if details.get('file_id') else {}
        data = {'external_id': key, 'event_type': event_type, 'occurred_at': datetime.now(timezone.utc).isoformat(), 'pc_name': socket.gethostname(), 'observation_method': method,
                **(current_user() if actor else {}), **{k: ids[k] for k in ['distribution_id', 'issuance_id'] if k in ids}, **details}
        self.enqueue('/api/agent/observations', data, 'observation:' + key)

    def monitor_volumes(self):
        current = {v['usb_device_id'] + ':' + v['drive']: v for v in usb_volumes() if v['usb_device_id']}
        previous = json.loads(self.state('usb_snapshot', 'null'))
        for key, info in current.items():
            if previous is None or key not in previous:
                self.observe('USB_PRESENT' if previous is None else 'USB_CONNECTED', 'VOLUME_SNAPSHOT_DIFF', actor=False, object_path=info['drive'], **{k: info[k] for k in ['storage_type', 'usb_device_id', 'volume_id']})
        if previous is not None:
            for key, info in previous.items():
                if key not in current:
                    self.observe('USB_DISCONNECTED', 'VOLUME_SNAPSHOT_DIFF', actor=False, object_path=info['drive'], **{k: info[k] for k in ['storage_type', 'usb_device_id', 'volume_id']})
        self.set_state('usb_snapshot', json.dumps(current))
        self.db.commit()

    def monitor_paths(self):
        from .windows_agent import sha256
        count = 0
        for root in self.roots:
            for folder, directories, files in os.walk(root, followlinks=False):
                directories[:] = [n for n in directories if not (getattr((Path(folder)/n).lstat(), 'st_reparse_tag', 0) & 0x20000000) and not (Path(folder)/n).is_symlink()]
                for name in files:
                    count += 1
                    if count > 10000: return
                    path = Path(folder) / name
                    try:
                        if path.is_symlink() or not self.approved_path(path): continue
                        identity = file_identity(path); old = self.identities.get(identity)
                        if not old or not old.get('path') or old['path'] == str(path): continue
                        if path.stat().st_size > 10 * 1024 * 1024 or sha256(path) != old['sha']: continue
                        kind = 'FILE_RENAMED' if Path(old['path']).parent == path.parent else 'FILE_MOVED'
                        self.observe(kind, 'STABLE_FILE_ID_SNAPSHOT', actor=False, file_id=old['file_id'], sha256=old['sha'], previous_path=old['path'], object_path=str(path), file_identity=identity, **storage_info(path.drive))
                        self.identities[identity] = {**old, 'path': str(path)}
                    except OSError:
                        continue
        self.set_state('identities', json.dumps(self.identities)); self.db.commit()

    def extract_zip(self, source, destination):
        from backend.archives import extract_verified
        self.refresh()
        source, destination = Path(source).resolve(), Path(destination).absolute()
        if not self.approved_path(destination):
            raise ValueError('Extraction destination must be within approved monitoring roots')
        with source.open('rb') as stream: raw = stream.read(50 * 1024 * 1024 + 1)
        sha = hashlib.sha256(raw).hexdigest()
        distribution = self.distributions.get(sha)
        if not distribution: raise ValueError('ZIP hash not in authenticated server manifest')
        from backend.archives import zip_entries
        entries = zip_entries(raw)
        for item in distribution['files']:
            if hashlib.sha256(entries.get(item['archive_path'], b'')).hexdigest() != item['file_hash']:
                raise ValueError('Distribution member integrity failure')
        extract_verified(raw, destination)
        self.observe('ZIP_EXTRACTED', 'APPROVED_EXTRACT_TOOL', distribution_id=distribution['distribution_id'], sha256=sha, object_path=str(destination.resolve()), process=os.path.abspath(os.sys.executable), process_id=str(os.getpid()))
        self.db.commit(); self.flush()
        return {'distribution_id': distribution['distribution_id'], 'destination': str(destination), 'status': 'EXTRACTED_LOCALLY'}
