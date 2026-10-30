"""DLP 로그 SQLite 저장소.

agent 로그는 재시작해도 남아야 하므로 SQLite 파일(DB_PATH)에 저장합니다.
알림/디코이 등 나머지 상태는 아직 인메모리 store(app/store.py)를 사용합니다.
"""
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

from app.config import settings
from app.models import EventType, LogRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id             TEXT PRIMARY KEY,
    received_at    TEXT NOT NULL,      -- UTC ISO8601(마이크로초 고정) → 문자열 비교로 기간 필터
    host           TEXT NOT NULL,
    user           TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    file_name      TEXT,
    file_hash      TEXT,
    classification TEXT,
    channel        TEXT,
    blocked        INTEGER NOT NULL,
    detail         TEXT NOT NULL       -- JSON
);
CREATE INDEX IF NOT EXISTS idx_logs_received_at ON logs (received_at);
CREATE INDEX IF NOT EXISTS idx_logs_host ON logs (host);
"""

_COLUMNS = (
    "id, received_at, host, user, event_type, file_name, file_hash,"
    " classification, channel, blocked, detail"
)


def _ts(dt: datetime) -> str:
    """시간대 없는 값은 UTC로 간주. 정렬·비교가 문자열로 되도록 형식을 고정."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _row_to_record(row: sqlite3.Row) -> LogRecord:
    return LogRecord(
        id=row["id"],
        received_at=datetime.fromisoformat(row["received_at"]),
        host=row["host"],
        user=row["user"],
        event_type=row["event_type"],
        file_name=row["file_name"],
        file_hash=row["file_hash"],
        classification=row["classification"],
        channel=row["channel"],
        blocked=bool(row["blocked"]),
        detail=json.loads(row["detail"]),
    )


class LogRepository:
    def __init__(self, path: str) -> None:
        self.path = path
        with closing(self._connect()) as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def add(self, log: LogRecord) -> LogRecord:
        with closing(self._connect()) as conn, conn:
            conn.execute(
                f"INSERT INTO logs ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    log.id, _ts(log.received_at), log.host, log.user, log.event_type.value,
                    log.file_name, log.file_hash, log.classification, log.channel,
                    int(log.blocked), json.dumps(log.detail, ensure_ascii=False),
                ),
            )
        return log

    def get(self, log_id: str) -> LogRecord | None:
        with closing(self._connect()) as conn:
            row = conn.execute(f"SELECT {_COLUMNS} FROM logs WHERE id = ?", (log_id,)).fetchone()
        return _row_to_record(row) if row else None

    def recent(self, n: int) -> list[LogRecord]:
        """분석 맥락용 최근 n건 (오래된 것 → 최신 순)."""
        items, _ = self.list(limit=n)
        return items[::-1]

    def list(
        self,
        *,
        host: str | None = None,
        user: str | None = None,
        event_type: EventType | None = None,
        classification: str | None = None,
        blocked: bool | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[LogRecord], int]:
        """최신순 목록과, 필터에 걸린 전체 건수를 함께 반환."""
        where: list[str] = []
        params: list = []
        for column, value in (
            ("host", host),
            ("user", user),
            ("event_type", event_type.value if event_type else None),
            ("classification", classification),
        ):
            if value is not None:
                where.append(f"{column} = ?")
                params.append(value)
        if blocked is not None:
            where.append("blocked = ?")
            params.append(int(blocked))
        if since is not None:
            where.append("received_at >= ?")
            params.append(_ts(since))
        if until is not None:
            where.append("received_at <= ?")
            params.append(_ts(until))
        clause = f"WHERE {' AND '.join(where)}" if where else ""

        with closing(self._connect()) as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM logs {clause}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT {_COLUMNS} FROM logs {clause}"
                " ORDER BY received_at DESC, rowid DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return [_row_to_record(r) for r in rows], total


_log_repo: LogRepository | None = None


def get_log_repo() -> LogRepository:
    """FastAPI 의존성. 첫 요청 시 DB 파일을 열고 테이블을 만든다."""
    global _log_repo
    if _log_repo is None:
        _log_repo = LogRepository(settings.db_path)
    return _log_repo
