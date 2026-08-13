"""Dashboard statistics schemas."""
from pydantic import BaseModel


class RiskDistributionItem(BaseModel):
    risk_level: str
    count: int


class ClassificationDistributionItem(BaseModel):
    classification: str
    count: int


class WeeklyStatItem(BaseModel):
    date: str
    total: int
    phishing: int
    malware: int
    critical: int


class MonthlyStatItem(BaseModel):
    month: str
    total: int
    phishing: int
    malware: int
    critical: int


class TopItem(BaseModel):
    label: str
    count: int


class StatsResponse(BaseModel):
    total_analyses: int
    phishing_detected: int
    malware_detected: int
    critical_alerts: int
    avg_risk_score: float
    avg_confidence: float
    risk_distribution: list[RiskDistributionItem]
    classification_distribution: list[ClassificationDistributionItem]
    weekly_stats: list[WeeklyStatItem]

    # --- SOC Dashboard additions (additive; safe defaults so older clients
    # deserializing this response are unaffected) ---
    analyses_today: int = 0
    avg_latency_ms: float = 0.0
    false_positive_rate: float = 0.0
    monthly_stats: list[MonthlyStatItem] = []
    top_ioc_types: list[TopItem] = []
    top_countries: list[TopItem] = []
    top_malware_families: list[TopItem] = []
    top_mitre_techniques: list[TopItem] = []
    top_owasp_categories: list[TopItem] = []
