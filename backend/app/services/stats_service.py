"""Dashboard statistics aggregation service."""
from sqlalchemy.orm import Session

from app.repositories.analysis_repository import AnalysisRepository
from app.schemas.stats import (
    ClassificationDistributionItem,
    RiskDistributionItem,
    StatsResponse,
    WeeklyStatItem,
)


class StatsService:
    def __init__(self, db: Session):
        self.repo = AnalysisRepository(db)

    def get_stats(self) -> StatsResponse:
        total = self.repo.count_all()
        # Phishing/Malware Detected are Threat Category counters: they derive
        # from the normalized `threat_tags` field (set deterministically in
        # enrichment_service.build_enrichment), NOT from `input_type`/Content
        # Type. A submitted "Phishing Email" only counts once the model
        # actually tags it "Phishing"; a Windows/Linux log tagged "Malware"
        # counts here even though its Content Type is a log, not an email.
        phishing = self.repo.count_with_threat_tag("Phishing")
        malware = self.repo.count_with_threat_tag("Malware")
        # Critical Alerts is a Severity counter: it derives from `risk_level`
        # (the Severity dimension), independent of classification/category.
        critical = self.repo.count_by_risk("Critical")

        risk_distribution = [
            RiskDistributionItem(risk_level=level, count=count)
            for level, count in self.repo.risk_distribution()
        ]
        classification_distribution = [
            ClassificationDistributionItem(classification=classification, count=count)
            for classification, count in self.repo.classification_distribution()
        ]

        weekly = [
            WeeklyStatItem(date=day, total=total_n, phishing=phishing_n, malware=malware_n, critical=critical_n)
            for day, total_n, phishing_n, malware_n, critical_n in self.repo.weekly_stats()
        ]

        return StatsResponse(
            total_analyses=total,
            phishing_detected=phishing,
            malware_detected=malware,
            critical_alerts=critical,
            avg_risk_score=round(self.repo.average_risk_score(), 1),
            avg_confidence=round(self.repo.average_confidence(), 1),
            risk_distribution=risk_distribution,
            classification_distribution=classification_distribution,
            weekly_stats=weekly,
        )
