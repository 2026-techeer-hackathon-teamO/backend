"""보안 담당자 알림 (Slack Incoming Webhook).

SLACK_WEBHOOK_URL 이 비어있으면 콘솔 로그로 폴백합니다 (해커톤 편의).
"""
import httpx

from app.config import settings


async def notify_slack(text: str) -> bool:
    if not settings.slack_webhook_url:
        print(f"[notifier] (Slack 미설정) {text}")
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(settings.slack_webhook_url, json={"text": text})
            return resp.status_code // 100 == 2
    except httpx.HTTPError as exc:
        print(f"[notifier] Slack 전송 실패: {exc}")
        return False
