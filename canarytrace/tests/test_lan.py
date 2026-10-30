import ipaddress
import ssl
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from scripts.prepare_lan import build_certificate


def test_lan_certificate_verified_https_and_wrong_host(tmp_path):
    key, cert = build_certificate('192.168.10.20')
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ipaddress.ip_address('192.168.10.20') in names.get_values_for_type(x509.IPAddress)
    assert 'localhost' in names.get_values_for_type(x509.DNSName)
    pem = tmp_path / 'cert.pem'; private = tmp_path / 'key.pem'
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b'TLS_VERIFIED')
        def log_message(self, *args): pass
    server = HTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(pem, private)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    try:
        with httpx.Client(verify=ssl.create_default_context(cafile=str(pem)), trust_env=False) as c:
            assert c.get(f'https://127.0.0.1:{server.server_port}').text == 'TLS_VERIFIED'
        with pytest.raises(httpx.ConnectError):
            httpx.get(f'https://127.0.0.1:{server.server_port}', trust_env=False)
        with socket.create_connection(('127.0.0.1', server.server_port)) as connection:
            with pytest.raises(ssl.SSLCertVerificationError):
                ssl.create_default_context(cafile=str(pem)).wrap_socket(connection, server_hostname='192.168.10.99')
    finally:
        server.shutdown(); server.server_close(); worker.join()


@pytest.mark.parametrize('host', ['8.8.8.8', '127.0.0.1', '169.254.1.1', 'example.com', '0.0.0.0'])
def test_lan_rejects_unapproved_network(host):
    with pytest.raises(ValueError): build_certificate(host)
