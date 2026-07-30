from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.config.settings import settings


def _engine_kwargs(url: str) -> dict:
    """Dialect-specific engine options (SQLite needs check_same_thread=False)."""
    if url.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False}}
    return {}


engine = create_engine(settings.DATABASE_URL, **_engine_kwargs(settings.DATABASE_URL))
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
