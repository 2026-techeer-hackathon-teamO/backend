"""Stage a reversible LAN TLS configuration. Does not activate network access."""
import argparse
import ipaddress
import json
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]


def build_certificate(host):
    ip = ipaddress.IPv4Address(host)
    if not any(ip in ipaddress.ip_network(n) for n in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']):
        raise ValueError('An explicit private LAN IPv4 address is required')
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CanaryTrace approved LAN test')])
    at = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(at-timedelta(minutes=5))
        .not_valid_after(at+timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip), x509.IPAddress(ipaddress.ip_address('127.0.0.1')), x509.DNSName('localhost')]), False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(key, hashes.SHA256()))
    return key, cert


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', required=True)
    a = p.parse_args()
    runtime = ROOT / '.runtime'
    key, cert = build_certificate(a.host)
    identifier = str(uuid.uuid4())
    stage = runtime / 'lan-setup' / identifier
    backup = stage / 'backup'; backup.mkdir(parents=True)
    for name in ['settings.json', 'tls/cert.pem', 'tls/key.pem']:
        target = backup / name; target.parent.mkdir(exist_ok=True)
        shutil.copy2(runtime / name, target)
    cfg = json.loads((runtime / 'settings.json').read_text('utf-8'))
    cfg.update(public_base_url=f'https://{a.host}:{cfg["port"]}', bind_host='0.0.0.0')
    (stage / 'settings.json').write_text(json.dumps(cfg, indent=2), 'utf-8')
    (stage / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (stage / 'cert.cer').write_bytes(cert.public_bytes(serialization.Encoding.DER))
    (stage / 'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    summary = {'stage': str(stage), 'host': a.host, 'url': cfg['public_base_url'], 'port': cfg['port'], 'firewall_rule': 'CanaryTrace-LAN-'+identifier, 'certificate_sha256': cert.fingerprint(hashes.SHA256()).hex(), 'status': 'PREPARED_NOT_ACTIVE', 'valid_until': cert.not_valid_after_utc.isoformat(), 'limitation': 'Same reachable LAN only; requires explicit client certificate trust. Does not configure router/NAT/public DNS.'}
    (stage / 'plan.json').write_text(json.dumps(summary, indent=2), 'utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__': main()
