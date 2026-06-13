from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime

from sqlalchemy import DateTime, Integer, LargeBinary, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


class SharedFile(Base):
    __tablename__ = "shared_files"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    public_name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    original_filename: Mapped[str] = mapped_column(String(500))
    stored_extension: Mapped[str] = mapped_column(String(32))
    content_type: Mapped[str] = mapped_column(String(160))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    blob_data: Mapped[bytes] = mapped_column(LargeBinary)
    thumbnail_data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    thumbnail_content_type: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_by_subject: Mapped[str] = mapped_column(String(300))
    created_by_username: Mapped[str] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    image_width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    image_height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    thumbnail_width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    thumbnail_height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")


def get_engine():
    return create_engine(get_settings().database_url, pool_pre_ping=True)


engine = get_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def migrate() -> None:
    Base.metadata.create_all(bind=engine)

