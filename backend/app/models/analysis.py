"""Analysis (threat triage result) and History model."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class Analysis(Base):
    """Stores each security-content analysis performed by the AI, acting as
    both the Analysis record and the History log entry for that analysis.
    """

    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )

    input_text: Mapped[str] = mapped_column(Text, nullable=False)
    input_type: Mapped[str] = mapped_column(String(50), default="unknown")

    classification: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)

    summary: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    recommendations: Mapped[list] = mapped_column(JSON, default=list)
    indicators: Mapped[list] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    iocs: Mapped[dict] = mapped_column(JSON, default=dict)

    model_used: Mapped[str] = mapped_column(String(100), default="gpt-4o-mini")
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)

    # --- Analyzer page enrichment (additive; nullable so older rows/deploys
    # created before this feature still load fine) ---
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    threat_tags: Mapped[list | None] = mapped_column(JSON, nullable=True)
    mitre_details: Mapped[list | None] = mapped_column(JSON, nullable=True)
    attack_timeline: Mapped[list | None] = mapped_column(JSON, nullable=True)
    explainability: Mapped[list | None] = mapped_column(JSON, nullable=True)
    recommendations_grouped: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    sigma_match: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    detection_metrics: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    threat_intel: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # --- Enterprise SOC additions (additive; nullable) ---
    owasp_mappings: Mapped[list | None] = mapped_column(JSON, nullable=True)
    risk_factors: Mapped[list | None] = mapped_column(JSON, nullable=True)
    knowledge_sources: Mapped[list | None] = mapped_column(JSON, nullable=True)
    playbook_actions: Mapped[list | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )

    owner = relationship("User", back_populates="analyses")
