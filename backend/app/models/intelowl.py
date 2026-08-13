"""IntelOwl scan persistence model (additive, nullable-friendly)."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class IntelOwlScan(Base):
    """One IntelOwl job for one observable, optionally tied to an analysis."""

    __tablename__ = "intelowl_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    analysis_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=True, index=True
    )
    observable: Mapped[str] = mapped_column(Text, nullable=False)
    observable_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    intelowl_job_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="PENDING", index=True)
    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    analyzers: Mapped[list | None] = mapped_column(JSON, nullable=True)
    connectors: Mapped[list | None] = mapped_column(JSON, nullable=True)
    raw_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    normalized_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_intelowl_scans_obs_type_created", "observable", "observable_type", "created_at"),
    )
