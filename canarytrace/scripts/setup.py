"""Create local credentials and a SAN certificate without modifying OS trust stores."""
import argparse
import ipaddress
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='localhost', help='Server DNS name or LAN IP for certificate and token links')
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8443)
    args = parser.parse_args()
    runtime = ROOT / '.runtime'
    runtime.mkdir(exist_ok=True)
    env_file = ROOT / '.env'
    env_text = env_file.read_text('utf-8') if env_file.exists() else ''
    additions = []
    if 'DATAGUARD_ADMIN_PASSWORD=' not in env_text:
        additions.append('DATAGUARD_ADMIN_PASSWORD=' + secrets.token_urlsafe(24))
    if 'DATAGUARD_INTEGRITY_KEY=' not in env_text:
        additions.append('DATAGUARD_INTEGRITY_KEY=' + secrets.token_hex(32))
    if additions:
        env_file.write_text(env_text + '\n' + '\n'.join(additions) + '\n', 'utf-8')
    config = runtime / 'settings.json'
    if config.exists():
        print('Existing configuration preserved. Edit settings.json and renew certificate explicitly for LAN deployment.')
        return
    tls = runtime / 'tls'
    tls.mkdir(exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'DataGuard local demo')])
    san = [x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1')), x509.IPAddress(ipaddress.ip_address('::1'))]
    if args.host != 'localhost':
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(args.host)))
        except ValueError:
            san.append(x509.DNSName(args.host))
    at = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(at - timedelta(minutes=5)).not_valid_after(at + timedelta(days=90)).add_extension(x509.SubjectAlternativeName(san), critical=False).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True).sign(key, hashes.SHA256())
    (tls / 'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (tls / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    settings = {'public_base_url': f'https://{args.host}:{args.port}', 'bind_host': args.bind, 'port': args.port, 'trusted_proxies': []}
    config.write_text(json.dumps(settings, indent=2), 'utf-8')
    print('Created .env (private credentials), .runtime/settings.json and .runtime/tls/cert.pem. Keep private files on this PC.')

if __name__ == '__main__':
    main()
