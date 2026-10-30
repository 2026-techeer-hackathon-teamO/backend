"""Deterministic local security analysis; no LLM or external model API."""
from datetime import datetime, timedelta


def analyze_event(event, recent):
    # 외부 AI API 없이 동작하는 설명 가능한 규칙 분석입니다. 정보 유출 확정 판정을 내리지 않습니다.
    score, reasons = 10, []
    activity = event.get('activity', '')
    if activity in {'AUTOMATED_SCAN_SUSPECTED', 'PREVIEW_OR_SHELL_CANDIDATE'}:
        reasons.append('Automated/preview candidate; human reading is not established')
    if event.get('policy_verdict') == 'EXTERNAL_SUSPECTED':
        score += 50
        reasons.append('Server observed address is outside allowed networks')
    if event.get('classification') == 'RESTRICTED':
        score += 15
        reasons.append('Restricted classification')
    if event.get('device_id'):
        cutoff = datetime.fromisoformat(event['occurred_at']) - timedelta(minutes=5)
        matching = [r for r in recent if r.get('device_id') == event['device_id'] and cutoff <= datetime.fromisoformat(r['occurred_at']) <= datetime.fromisoformat(event['occurred_at']) and r.get('activity') == 'INTERACTIVE_PROCESS_CANDIDATE']
        if len({r['file_id'] for r in matching}) >= 5:
            score += 25
            reasons.append('Five or more distinct confidential files accessed in five minutes')
    return {'engine': 'LOCAL_RULES_V1', 'model_used': False, 'risk_score': min(score, 100), 'reasons': reasons, 'conclusion': 'REVIEW_REQUIRED' if score >= 50 else 'OBSERVATION_ONLY', 'exfiltration_confirmed': False}
