"""
Database engine + session management.

Uses SQLAlchemy 2.0 style. SQLite is the default so the project runs with
zero external services for grading/demo purposes; swapping DATABASE_URL to
Postgres in .env requires no code changes elsewhere.
"""
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

# SQLite needs this connect_arg when used from multiple threads (FastAPI's
# default threadpool for sync path operations spawns new threads per request).
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(
    bind=engine, autoflush=False, autocommit=False, future=True,
    # Without this, attributes on an object are expired after commit and any
    # access after the session/`with db_session()` block closes raises
    # DetachedInstanceError. Several call sites (ScanService background-task
    # methods, the websocket handler) intentionally read attributes off
    # objects after their short-lived session has closed, so we keep
    # attributes populated post-commit instead of forcing every caller to
    # extract primitives before the `with` block ends.
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Shared declarative base for every ORM model in the app."""
    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yields a request-scoped session, always closed."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def db_session() -> Generator[Session, None, None]:
    """Context-manager variant for use outside request handlers (e.g. seed scripts, background tasks)."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """Create all tables. Called once at startup (see app/main.py)."""
    from app.models import user, scan, vulnerability, api_key  # noqa: F401 — register models on Base
    Base.metadata.create_all(bind=engine)
