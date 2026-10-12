"""SQLAlchemy engine/session management and database initialisation."""
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def make_engine(database_url: str) -> Engine:
    kwargs: dict = {"future": True}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url or database_url in ("sqlite://", "sqlite:///"):
            kwargs["poolclass"] = StaticPool
        else:
            path = database_url.replace("sqlite:///", "", 1)
            Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(database_url, **kwargs)
    if database_url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn, _):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
    return engine


def make_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)


def init_db(engine: Engine, session_factory: sessionmaker) -> None:
    """Create tables and seed the safe default policies (idempotent)."""
    from app import models  # noqa: F401  (registers tables)
    from app.services.default_policies import seed_default_policies

    Base.metadata.create_all(bind=engine)
    with session_factory() as db:
        seed_default_policies(db)


def session_dependency(session_factory: sessionmaker):
    def _get_db() -> Iterator[Session]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    return _get_db
