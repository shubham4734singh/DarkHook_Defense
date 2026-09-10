import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from core.config import settings

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SQLITE_DB_PATH = settings.SQLITE_DB_PATH if getattr(settings, "SQLITE_DB_PATH", None) else os.path.join(BASE_DIR, "darkhook_defense.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{SQLITE_DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_sqlite_db():
    """Dependency for obtaining a SQLite database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_sqlite_db():
    """Create all SQLite database tables if they do not already exist."""
    from models.scan_history import ScanHistory  # noqa: F401
    Base.metadata.create_all(bind=engine)
    print(f"[+] SQLite database initialized at: {SQLITE_DB_PATH}")
