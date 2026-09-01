"""User model — accounts, RBAC role, verification & reset state."""
import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum as SAEnum, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole), default=UserRole.USER, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    notify_email_on_scan_complete: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notify_email_on_critical_vuln: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notify_weekly_digest: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    avatar_color: Mapped[str] = mapped_column(String(7), default="#00D4B8", nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scans = relationship("Scan", back_populates="owner", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="owner", cascade="all, delete-orphan")

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN
