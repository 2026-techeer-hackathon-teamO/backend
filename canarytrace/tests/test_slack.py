import asyncio
import httpx
import pytest
from backend.notifications import enqueue, deliver_once, validate_webhook
from backend.db import now, rows


@pytest.mark.parametrize('status,text,result',[(200,'ok','SENT'),(429,'rate_limited','RETRY'),(500,'error','RETRY'),(403,'invalid_token','FAILED'),(200,'unexpected','FAILED')])
def test_slack_delivery_mock(system,status,text,result):
    # 실제 Slack 전송이 아닌 HTTP 어댑터 테스트입니다. 실전 전송에는 승인된 Webhook이 필요합니다.
    Session=system['app'].state.Session
    with Session.begin() as db:
        enqueue(db,{'event_id':'test-event','file_name':'test.txt','file_id':'file-1','occurred_at':now(),'observed_public_ip':'127.0.0.1','source_type':'TOKEN_URL'},True)
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:httpx.Response(status,text=text))) as c:
            await deliver_once(Session,'https://hooks.slack.com/services/TEST/ONLY/TEST',c)
    asyncio.run(run())
    with Session() as db:
        row=rows(db,'notification')[0]
        assert row.data['status']==result and row.data['attempts']==1


@pytest.mark.parametrize('url',['http://hooks.slack.com/services/a','https://evil.test/services/a','https://hooks.slack.com.evil.test/services/a','https://user@hooks.slack.com/services/a'])
def test_webhook_destination_validation(url):
    with pytest.raises(ValueError):validate_webhook(url)
