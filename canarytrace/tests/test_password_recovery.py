import pytest

from backend.db import Record, rows
from backend.security import record_signature
from scripts.reset_admin_password import reset_admin


def test_password_recovery_revokes_sessions_and_preserves_data(system):
    s = system
    cfg = s['cfg']
    password = 'Recovered-admin-password-2026'
    assert reset_admin(cfg['runtime'], password, cfg['integrity_key'])
    c = s['client']
    assert c.get('/api/summary', headers=s['headers']).status_code == 401
    assert c.post('/api/login', json={'username': 'admin', 'password': cfg['admin_password']}).status_code == 401
    response = c.post('/api/login', json={'username': 'admin', 'password': password})
    assert response.status_code == 200
    with s['app'].state.Session() as db:
        assert db.get(Record, s['file']['id']) is not None
        account = db.get(Record, 'admin')
        assert account.seal == record_signature(cfg['integrity_key'], account)
        assert any(row.data['action'] == 'ADMIN_PASSWORD_RESET' for row in rows(db, 'audit'))
    assert not reset_admin(cfg['runtime'], password, cfg['integrity_key'])
    headers = {'Authorization': 'Bearer ' + response.json()['access_token']}
    assert c.get('/api/summary', headers=headers).status_code == 200


def test_password_recovery_rejects_wrong_integrity_key(system):
    s = system
    with pytest.raises(ValueError, match='integrity verification failed'):
        reset_admin(s['cfg']['runtime'], 'Recovered-admin-password-2026', 'wrong-integrity-key-' * 3)
    assert s['client'].get('/api/summary', headers=s['headers']).status_code == 200
