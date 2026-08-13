"""Cache of recent VirusTotal/Shodan/AbuseIPDB lookup results.

Keyed by (source, indicator_type, indicator). A fresh row lets
threat_intel_service reuse a recent result instead of re-querying the
external API for an indicator seen in an earlier analysis, which matters a
lot for free-tier rate limits (e.g. VirusTotal's public API).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class ThreatIntelCacheEntry(Base):
    __tablename__ = "threat_intel_cache"
    __table_args__ = (
        UniqueConstraint("source", "indicator_type", "indicator", name="uq_threat_intel_cache_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    indicator_type: Mapped[str] = mapped_column(String(16), nullable=False)
    indicator: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    result: Mapped[dict] = mapped_column(JSON, nullable=False)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
