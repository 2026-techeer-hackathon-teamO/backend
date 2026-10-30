"""Tests for the LLM-driven Deception Engine & Zero-Access Confidential Policy."""

from app.db import DecoyRepository
from app.models import EventType, LogRecord, Severity
from app.services.analyzer import analyze
from app.services.decoy import synthesize_transparent_decoy, synthesize_decoy_text
from app.store import store


def test_zero_access_confidential_policy_instant_high_alert():
    """모든 접근이 불가한 기밀 파일은 단순 열람(file_access)만 발생해도 즉시 HIGH 알림이어야 한다."""
    record = LogRecord(
        host="SEC-PC-01",
        user="attacker",
        event_type=EventType.FILE_ACCESS,
        file_name="project_alpha_design.txt",
        classification="confidential",
    )
    import asyncio
    alert = asyncio.run(analyze(record, []))

    assert alert is not None
    assert alert.severity == Severity.HIGH
    assert alert.score == 1.0
    assert "Zero-Access" in alert.reason
    assert "project_alpha_design.txt" in alert.reason


def test_llm_decoy_synthesis_content_and_canary_injection():
    """합성된 디코이 문서는 실제 기밀과 유사한 맥락과 카나리 비콘 URL, 가짜 AWS 키를 포함해야 한다."""
    file_name = "project_alpha_production_api_key.txt"
    decoy, canary_url = synthesize_transparent_decoy(file_name)

    assert decoy.id
    assert decoy.token_id
    assert decoy.sha256 is not None
    assert decoy.size is not None and decoy.size > 0
    assert f"/api/canary/{decoy.token_id}" in canary_url

    # Check synthetic content
    content = synthesize_decoy_text(file_name, canary_url, decoy.token_id)
    assert "AKIA" in content  # Fake AWS Access Key format
    assert canary_url in content  # Embedded Canary Beacon
    assert "PROJECT_ALPHA" in content.upper()


def test_api_decoys_synthesize_endpoint(client, decoy_repo):
    """POST /api/decoys/synthesize 엔드포인트 호출 시 파일 바이트와 해시가 자동 저장되어야 한다."""
    resp = client.post("/api/decoys/synthesize", params={"file_name": "project_alpha_server_config.txt"})
    assert resp.status_code == 200
    data = resp.json()

    decoy_id = data["decoy"]["id"]
    token_id = data["decoy"]["token_id"]
    canary_url = data["canary_url"]

    assert f"/api/canary/{token_id}" in canary_url

    # Check agent decoy list has the synthesized file
    agent_decoys = client.get("/api/agent/decoys").json()
    assert any(d["id"] == decoy_id for d in agent_decoys)

    # Check raw file download
    file_resp = client.get(f"/api/agent/decoys/{decoy_id}/file")
    assert file_resp.status_code == 200
    assert "AKIA" in file_resp.text
    assert canary_url in file_resp.text

