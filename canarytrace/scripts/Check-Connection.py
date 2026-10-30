"""Pinned CA validation for the public LAN installation kit; no credentials used."""
import hashlib
import json
import ssl
import urllib.request
from pathlib import Path
root = Path(__file__).resolve().parent
config = json.loads((root/'connection.json').read_text('utf-8-sig'))
assert hashlib.sha256((root/'server-cert.cer').read_bytes()).hexdigest() == config['certificate_sha256'], 'Certificate fingerprint mismatch'
context = ssl.create_default_context(cafile=str(root/'server-cert.pem'))
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
with opener.open(config['server']+'/api/health', timeout=15) as response:
    data = json.load(response)
    assert data['service'] == 'DataGuard' and data['status'] == 'ok'
print('Verified HTTPS connection: '+config['server'])
