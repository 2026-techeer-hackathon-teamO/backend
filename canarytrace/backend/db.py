import uuid
from datetime import datetime, timezone
from sqlalchemy import JSON, String, create_engine, select, event, inspect, text
from .security import record_signature
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Base(DeclarativeBase):
    pass


class Record(Base):
    __tablename__ = 'records'
    id: Mapped[str] = mapped_column(String, primary_key=True)
    kind: Mapped[str] = mapped_column(String, index=True)
    created_at: Mapped[str] = mapped_column(String, index=True)
    dedup_key: Mapped[str | None] = mapped_column(String, unique=True, nullable=True)
    data: Mapped[dict] = mapped_column(JSON)
    seal: Mapped[str | None] = mapped_column(String, nullable=True)


def connect(path, integrity_key=None):
    # 기존 DB를 보존하면서 무결성 컬럼을 추가합니다. 예전 미서명 레코드는 검증됨으로 위장하지 않습니다.
    engine = create_engine(f'sqlite:///{path}', connect_args={'check_same_thread': False, 'timeout': 30})
    @event.listens_for(engine, 'connect')
    def configure(dbapi, _):
        dbapi.execute('PRAGMA journal_mode=WAL')
        dbapi.execute('PRAGMA busy_timeout=30000')
    Base.metadata.create_all(engine)
    if 'seal' not in {c['name'] for c in inspect(engine).get_columns('records')}:
        with engine.begin() as connection:
            connection.execute(text('ALTER TABLE records ADD COLUMN seal VARCHAR'))
    factory = sessionmaker(engine, expire_on_commit=False)
    if integrity_key:
        @event.listens_for(factory, 'before_flush')
        def seal_records(db, _, __):
            for row in db.new.union(db.dirty):
                if isinstance(row, Record):
                    row.seal = record_signature(integrity_key, row)
    return factory, engine


def add(db, kind, data, *, id=None, dedup_key=None):
    row = Record(id=id or str(uuid.uuid4()), kind=kind, created_at=now(), data=data, dedup_key=dedup_key)
    db.add(row)
    return row


def rows(db, kind):
    return db.scalars(select(Record).where(Record.kind == kind).order_by(Record.created_at.desc())).all()


def public(row):
    return {'id': row.id, 'created_at': row.created_at, **row.data}


def audit(db, actor, action, target, **details):
    return add(db, 'audit', {'actor': actor, 'action': action, 'target_id': target, **details})
