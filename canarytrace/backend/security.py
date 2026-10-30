"""Security primitives. Never trust forwarding headers without an explicit peer allowlist."""
import hashlib
import hmac
import ipaddress
import os
import secrets
import time
import json
from collections import defaultdict, deque
from fastapi import HTTPException


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    value = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 600_000)
    return f'{salt}:{value.hex()}'


def password_ok(password: str, stored: str) -> bool:
    salt, expected = stored.split(':')
    value = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 600_000)
    return hmac.compare_digest(value.hex(), expected)


def in_networks(address: str, networks: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in ipaddress.ip_network(net) for net in networks)
    except ValueError:
        return False


def observed_ip(peer: str, forwarded: str | None, trusted: list[str]) -> str:
    try:
        peer = str(ipaddress.ip_address(peer))
    except ValueError:
        return 'UNKNOWN'
    if not forwarded or not in_networks(peer, trusted):
        return peer
    try:
        chain = [str(ipaddress.ip_address(x.strip())) for x in forwarded.split(',')]
        if len(chain) > 20:
            return peer
    except ValueError:
        return peer
    current = peer
    for hop in reversed(chain):
        if not in_networks(current, trusted):
            break
        current = hop
    return current


def process_classification(process: str) -> str:
    name = process.replace('\\', '/').rsplit('/', 1)[-1].lower()
    if name in {'msmpeng.exe', 'mssense.exe', 'searchindexer.exe', 'searchprotocolhost.exe', 'savservice.exe'}:
        return 'AUTOMATED_SCAN_SUSPECTED'
    if name in {'prevhost.exe', 'dllhost.exe', 'explorer.exe'}:
        return 'PREVIEW_OR_SHELL_CANDIDATE'
    if name in {'notepad.exe', 'winword.exe', 'acrord32.exe', 'acrobat.exe', 'wordpad.exe'}:
        return 'INTERACTIVE_PROCESS_CANDIDATE'
    return 'FILE_ACCESS_ONLY'


def process_category(process):
    name = process.replace('\\', '/').rsplit('/', 1)[-1].lower()
    if name in {'searchindexer.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe'}: return 'SEARCH_INDEXING'
    if name in {'msmpeng.exe', 'mssense.exe', 'savservice.exe'}: return 'ANTIVIRUS_SCAN'
    if name in {'prevhost.exe', 'dllhost.exe', 'explorer.exe'}: return 'EXPLORER_OR_PREVIEW'
    if name in {'notepad.exe', 'winword.exe', 'acrord32.exe', 'acrobat.exe', 'wordpad.exe'}: return 'USER_APPLICATION_CANDIDATE'
    return 'OTHER_FILE_READ'


def event_signature(key, timestamp, path, body):
    material = timestamp.encode() + b'\n' + path.encode() + b'\n' + body
    return hmac.new(bytes.fromhex(digest(key)), material, hashlib.sha256).hexdigest()


def record_signature(key, row):
    material = json.dumps([row.id, row.kind, row.created_at, row.dedup_key, row.data], sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    return hmac.new(key.encode(), material, hashlib.sha256).hexdigest()


def scanner_suspected(method: str, ua: str) -> bool:
    return method == 'HEAD' or any(x in ua.lower() for x in ('proofpoint', 'safelinks', 'mimecast', 'barracuda', 'crawler', 'bot', 'scanner'))


def network_verdict(address, networks, *, scanner=False, blocked=False):
    # 프록시 신뢰 검증을 거친 주소만 분류합니다. VPN/NAT 뒤 개인의 신원은 판정하지 않습니다.
    if scanner:
        return 'SUSPECTED_SCANNER'
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return 'UNKNOWN_NETWORK'
    if blocked:
        return 'POLICY_VIOLATION'
    return 'INTERNAL_ACCESS' if in_networks(address, networks) else 'EXTERNAL_ACCESS'


class RateLimiter:
    def __init__(self):
        self.entries = defaultdict(deque)

    def check(self, key: str, limit: int, seconds: int = 60):
        now = time.monotonic()
        if len(self.entries) > 10000:
            self.entries = defaultdict(deque, {k: v for k, v in self.entries.items() if v and v[-1] > now - seconds})
        q = self.entries[key]
        while q and q[0] <= now - seconds:
            q.popleft()
        if len(q) >= limit:
            raise HTTPException(429, 'Request rate exceeded', headers={'Retry-After': str(seconds)})
        q.append(now)
