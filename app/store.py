"""해커톤용 인메모리 저장소. 추후 DB(SQLite/Postgres)로 교체.

프로세스 메모리에만 저장되므로 재시작 시 초기화됩니다.
"""
from app.models import Alert, CanaryHit, Decoy, LogRecord


class Store:
    def __init__(self) -> None:
        self.logs: list[LogRecord] = []
        self.alerts: list[Alert] = []
        self.decoys: list[Decoy] = []
        self.canary_hits: list[CanaryHit] = []

    def add_log(self, log: LogRecord) -> LogRecord:
        self.logs.append(log)
        return log

    def add_alert(self, alert: Alert) -> Alert:
        self.alerts.append(alert)
        return alert

    def add_decoy(self, decoy: Decoy) -> Decoy:
        self.decoys.append(decoy)
        return decoy

    def find_decoy_by_token(self, token_id: str) -> Decoy | None:
        return next((d for d in self.decoys if d.token_id == token_id), None)

    def add_canary_hit(self, hit: CanaryHit) -> CanaryHit:
        self.canary_hits.append(hit)
        return hit


store = Store()
