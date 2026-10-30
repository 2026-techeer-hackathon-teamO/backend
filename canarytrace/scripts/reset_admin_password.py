"""Explicitly restore the local admin password from .env without printing secrets."""
import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from dotenv import dotenv_values, set_key

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.db import Record, audit, connect, rows
from backend.security import password_hash, password_ok, record_signature


def reset_admin(runtime, password, integrity_key):
    if not password or not 12 <= len(password) <= 200:
        raise ValueError('DATAGUARD_ADMIN_PASSWORD must contain 12 to 200 characters')
    if not integrity_key or len(integrity_key) < 32:
        raise ValueError('A valid DATAGUARD_INTEGRITY_KEY is required')
    if not (runtime / 'dataguard.db').is_file():
        raise ValueError('Existing database not found')
    Session, engine = connect(runtime / 'dataguard.db', integrity_key)
    try:
        with Session.begin() as db:
            account = db.get(Record, 'admin')
            if not account or account.kind != 'user' or account.data.get('username') != 'admin' or account.data.get('role') != 'admin':
                raise ValueError('Expected administrator account not found')
            if account.seal != record_signature(integrity_key, account):
                raise ValueError('Administrator integrity verification failed; no password changed')
            if password_ok(password, account.data['password']):
                return False
            account.data = {**account.data, 'password': password_hash(password)}
            for session in rows(db, 'session'):
                if session.data.get('user_id') == account.id:
                    db.delete(session)
            audit(db, 'local-operator', 'ADMIN_PASSWORD_RESET', account.id, source='local .env')
        return True
    finally:
        engine.dispose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generate', action='store_true', help='Generate a new password and save it to .env')
    args = parser.parse_args()
    env = dotenv_values(ROOT / '.env')
    runtime = Path(os.getenv('DATAGUARD_RUNTIME') or env.get('DATAGUARD_RUNTIME') or ROOT / '.runtime')
    config = json.loads((runtime / 'settings.json').read_text('utf-8'))
    key = config.get('integrity_key') or os.getenv('DATAGUARD_INTEGRITY_KEY') or env.get('DATAGUARD_INTEGRITY_KEY')
    password = secrets.token_urlsafe(24) if args.generate else env.get('DATAGUARD_ADMIN_PASSWORD')
    changed = reset_admin(runtime, password, key)
    if args.generate:
        set_key(str(ROOT / '.env'), 'DATAGUARD_ADMIN_PASSWORD', password)
        print('New password saved to .env as DATAGUARD_ADMIN_PASSWORD.')
    print('Admin password restored from .env; previous admin sessions revoked.' if changed else 'Admin password already matches .env.')


if __name__ == '__main__':
    main()
