"""Per-user application settings."""
import uuid

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class UserSettings(Base):
    __tablename__ = "user_settings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), unique=True
    )
    theme: Mapped[str] = mapped_column(String(10), default="light")
    preferred_model: Mapped[str] = mapped_column(String(100), default="gpt-4o-mini")
    email_notifications: Mapped[bool] = mapped_column(Boolean, default=True)

    owner = relationship("User", back_populates="settings")
