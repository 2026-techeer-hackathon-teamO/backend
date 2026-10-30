"""Durable, bounded Slack delivery. No webhook URLs or secrets in logs/DB."""
import asyncio
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
import httpx
from sqlalchemy import select
from .db import Record, add, audit, now


def validate_webhook(url):
    if not url:
        return
    p = urlparse(url)
    if p.scheme != 'https' or p.hostname != 'hooks.slack.com' or not p.path.startswith('/services/') or p.username or p.port not in (None, 443) or p.query or p.fragment:
        raise ValueError('Slack webhook must be https://hooks.slack.com/services/...')


def enqueue(db, event, configured):
    # Webhook 미설정은 성공으로 처리하지 않습니다. 원본 이벤트 ID와 연결하여 전송 상태를 보존합니다.
    return add(db, 'notification', {'event_id': event['event_id'], 'status': 'PENDING' if configured else 'NOT_CONFIGURED', 'attempts': 0, 'next_attempt': now(), 'payload': {'text': f"[DataGuard] Canary request observed\nFile: {event['file_name']} ({event['file_id']})\nTime: {event['occurred_at']}\nServer observed IP: {event['observed_public_ip']}\nSource: {event['source_type']}\nURL/image request only; human reading, location and PC identity are not confirmed."}}, dedup_key='slack:' + event['event_id'])


async def deliver_once(Session, webhook, client):
    # 일시 오류만 제한 횟수 재시도합니다. 서버가 응답하기 전 끊기면 Slack에 중복 도착할 수 있습니다.
    if not webhook:
        return
    with Session() as db:
        pending = db.scalars(select(Record).where(Record.kind == 'notification').order_by(Record.created_at)).all()
        for row in pending:
            data = row.data
            if data['status'] not in {'PENDING', 'RETRY'} or data['next_attempt'] > now():
                continue
            attempts = data['attempts'] + 1
            status, reason = 'SENT', None
            try:
                response = await client.post(webhook, json=data['payload'])
                if response.status_code != 200 or response.text.strip() != 'ok':
                    reason = f'HTTP {response.status_code}; Slack did not acknowledge'
                    status = 'RETRY' if response.status_code in {429, 500, 502, 503, 504} else 'FAILED'
            except httpx.HTTPError:
                status, reason = 'RETRY', 'Network/TLS error'
            if attempts >= 5 and status == 'RETRY':
                status = 'FAILED'
            row.data = {**data, 'attempts': attempts, 'status': status, 'reason': reason, 'updated_at': now(), 'next_attempt': (datetime.now(timezone.utc) + timedelta(seconds=min(300, 2 ** attempts * 5))).isoformat()}
            audit(db, 'slack-worker', 'SLACK_' + status, data['event_id'])
            db.commit()
            return  # At most one message per worker tick; single server worker supported.


async def worker(Session, webhook, stop):
    async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
        while not stop.is_set():
            try:
                await deliver_once(Session, webhook, client)
            except Exception:
                # A DB error must not terminate delivery permanently or expose a webhook.
                import logging
                logging.getLogger('dataguard.slack').error('Notification processing failed; will retry')
            try:
                await asyncio.wait_for(stop.wait(), timeout=2)
            except asyncio.TimeoutError:
                pass
