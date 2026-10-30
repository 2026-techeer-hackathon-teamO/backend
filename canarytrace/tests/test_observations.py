"""Synthetic observations; these do not attest physical USB or PC-B operation."""
import hashlib
import io
import json
import zipfile
import pytest
from test_agent import agent

def test_usb_inventory_transitions_synthetic(agent, monkeypatch):
    a, _ = agent
    state = []
    monkeypatch.setattr('agent.observations.usb_volumes', lambda: state)
    a.monitor_volumes()
    assert a.db.execute('SELECT COUNT(*) FROM pending').fetchone()[0] == 0
    state.append({'drive': 'X:', 'storage_type': 'USB', 'usb_device_id': 'SYNTHETIC-USB', 'volume_id': 'SYNTHETIC-VOLUME'})
    a.monitor_volumes(); a.monitor_volumes(); state.clear(); a.monitor_volumes()
    events = [json.loads(r[0])['event_type'] for r in a.db.execute('SELECT payload FROM pending')]
    assert events == ['USB_CONNECTED', 'USB_DISCONNECTED']


def test_stable_file_id_rename_snapshot(agent):
    a, path = agent
    destination = path.with_name('renamed.txt'); path.rename(destination)
    a.monitor_paths()
    payload = json.loads(a.db.execute('SELECT payload FROM pending').fetchone()[0])
    assert payload['event_type'] == 'FILE_RENAMED' and payload['previous_path'] == str(path)
    assert payload.get('windows_user') is None  # Snapshot does not establish the actor.


def test_copy_lifecycle_synthetic_usb(agent, monkeypatch):
    a, path = agent
    monkeypatch.setattr(a, 'refresh', lambda: None); monkeypatch.setattr(a, 'flush', lambda: None)
    monkeypatch.setattr('agent.observations.current_user', lambda: {'windows_user': 'TEST-USER', 'windows_sid': 'TEST-SID'})
    class FakeStorage:
        def cache_clear(self): pass
        def __call__(self, drive): return {'storage_type': 'USB', 'usb_device_id': 'SYNTHETIC-USB', 'volume_id': 'SYNTHETIC-VOLUME'}
    monkeypatch.setattr('agent.windows_agent.storage_info', FakeStorage())
    target = path.with_name('usb-copy.txt')
    result = a.copy_usb(path, target)
    assert target.read_bytes() == path.read_bytes() and result['copy_observed']
    events = [json.loads(r[0]).get('event_type') for r in a.db.execute("SELECT payload FROM pending WHERE path='/api/agent/observations'")]
    assert events == ['COPY_ATTEMPT', 'FILE_WRITE_COMPLETED']
    with pytest.raises(ValueError, match='overwrite'): a.copy_usb(path, target)


def test_extract_tool_registered_zip(agent, monkeypatch):
    a, path = agent; raw = path.read_bytes(); out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as z: z.writestr('test.txt', raw)
    source = path.with_suffix('.zip'); source.write_bytes(out.getvalue())
    a.distributions = {hashlib.sha256(out.getvalue()).hexdigest(): {'distribution_id': 'test-dist', 'files': [{'archive_path': 'test.txt', 'file_hash': hashlib.sha256(raw).hexdigest()}]}}
    monkeypatch.setattr(a, 'refresh', lambda: None); monkeypatch.setattr(a, 'flush', lambda: None)
    monkeypatch.setattr('agent.observations.current_user', lambda: {'windows_user': 'TEST'})
    result = a.extract_zip(source, path.parent / 'extracted')
    assert result['status'] == 'EXTRACTED_LOCALLY'
    assert json.loads(a.db.execute('SELECT payload FROM pending').fetchone()[0])['event_type'] == 'ZIP_EXTRACTED'
    with pytest.raises(ValueError): a.extract_zip(source, path.parent.parent / 'outside')
