"""해커톤용 인메모리 저장소 (알림/카나리 히트). 로그·디코이는 app/db.py(SQLite).

프로세스 메모리에만 저장되므로 재시작 시 초기화됩니다.
"""
from app.models import Alert, CanaryHit


class Store:
    def __init__(self) -> None:
        self.alerts: list[Alert] = []
        self.canary_hits: list[CanaryHit] = []

    def add_alert(self, alert: Alert) -> Alert:
        self.alerts.append(alert)
        return alert

    def add_canary_hit(self, hit: CanaryHit) -> CanaryHit:
        self.canary_hits.append(hit)
        return hit


store = Store()
