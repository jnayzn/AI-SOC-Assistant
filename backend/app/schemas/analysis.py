"""Pydantic schemas for the analysis endpoints and the structured LLM output."""
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ThreatClassification(str, Enum):
    BENIGN = "Benign"
    SPAM = "Spam"
    SUSPICIOUS = "Suspicious"
    PHISHING = "Phishing"
    MALWARE = "Malware"
    CREDENTIAL_THEFT = "Credential Theft"
    BEC = "Business Email Compromise"
    DATA_EXFILTRATION = "Data Exfiltration"
    UNKNOWN = "Unknown"


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AnalyzeRequest(BaseModel):
    content: str = Field(
        ..., min_length=3, max_length=20000, description="Raw email, alert, or log text to analyze."
    )
    input_type: Optional[str] = Field(
        default="unknown",
        description="Hint: email | soc_alert | windows_log | linux_log | other",
    )

    @field_validator("content")
    @classmethod
    def strip_content(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("content must not be empty")
        return v


class IOCResult(BaseModel):
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)


class LLMAnalysisResult(BaseModel):
    """The strict JSON schema the LLM must return."""

    classification: ThreatClassification
    risk_level: RiskLevel
    confidence: int = Field(..., ge=0, le=100)
    summary: str
    explanation: str
    indicators: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class MitreTechniqueDetail(BaseModel):
    """MITRE ATT&CK technique enriched with tactic + description from the
    local knowledge base (not trusted from the LLM directly)."""

    id: str
    name: str
    tactic_id: str
    tactic_name: str
    description: str


class ExplainabilityItem(BaseModel):
    label: str
    matched: bool


class OwaspMapping(BaseModel):
    """OWASP Top 10 (2021) category mapped from deterministic explainability
    signals/classification -- narrative context, not a claim that this is a
    web-app vulnerability scan (see app/services/enrichment_service.py)."""

    id: str
    name: str
    reason: str


class PlaybookAction(BaseModel):
    """A single recommended SOC response action with a priority, generated
    deterministically from the threat category + severity of the analysis."""

    action: str
    priority: str  # "Critical" | "High" | "Medium" | "Low"
    category: str  # "Containment" | "Eradication" | "Forensics" | "Investigation" | "Communication"


class RecommendationsGrouped(BaseModel):
    immediate: list[str] = Field(default_factory=list)
    investigate: list[str] = Field(default_factory=list)
    contain: list[str] = Field(default_factory=list)
    recover: list[str] = Field(default_factory=list)


class SigmaMatch(BaseModel):
    rule_name: str
    matched: bool
    matched_indicators: list[str] = Field(default_factory=list)


class DetectionMetrics(BaseModel):
    detection_confidence: int
    malicious_probability: int
    suspicious_probability: int
    false_positive_probability: int


class LocalIocFinding(BaseModel):
    """Zero-dependency local enrichment for a single IOC, computed without any
    external API key. Always populated (graceful fallback per requirement),
    independent of whether VirusTotal/Shodan/AbuseIPDB are configured."""

    indicator: str
    indicator_type: str  # "ip" | "domain" | "url" | "hash" | "email"
    ip_class: Optional[str] = None
    hash_algorithm: Optional[str] = None
    tld: Optional[str] = None
    risk_level: RiskLevel
    threat_score: int = Field(..., ge=0, le=100)
    confidence: int = Field(..., ge=0, le=100)
    notes: list[str] = Field(default_factory=list)


class ThreatIntelVerdict(str, Enum):
    MALICIOUS = "Malicious"
    SUSPICIOUS = "Suspicious"
    HARMLESS = "Harmless"
    UNKNOWN = "Unknown"


class ThreatIntelFinding(BaseModel):
    """A single live lookup result for one IOC against one external source."""

    source: str  # "VirusTotal" | "Shodan" | "AbuseIPDB"
    indicator: str
    indicator_type: str  # "ip" | "domain" | "url" | "hash"
    verdict: ThreatIntelVerdict = ThreatIntelVerdict.UNKNOWN
    summary: str
    detail_url: Optional[str] = None
    malicious_engines: Optional[int] = None
    total_engines: Optional[int] = None
    error: Optional[str] = None
    checked_at: datetime
    from_cache: bool = False
    # --- Advanced IOC enrichment (additive; best-effort per source) ---
    country: Optional[str] = None
    asn: Optional[str] = None
    reverse_dns: Optional[str] = None
    malware_family: Optional[str] = None
    blacklist_count: Optional[int] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class ThreatIntelEnrichment(BaseModel):
    """Live external threat-intelligence lookups (VirusTotal + Shodan +
    AbuseIPDB) for the IOCs extracted from this analysis. Best-effort:
    `*_configured` reflects whether an API key is set, independent of
    whether any IOC was found or any lookup succeeded."""

    virustotal_configured: bool = False
    shodan_configured: bool = False
    abuseipdb_configured: bool = False
    findings: list[ThreatIntelFinding] = Field(default_factory=list)
    # Zero-dependency local heuristics, always populated regardless of
    # whether any API key above is configured (graceful fallback).
    local_findings: list[LocalIocFinding] = Field(default_factory=list)


class AnalysisEnrichment(BaseModel):
    """Deterministic additions computed server-side on top of the raw LLM
    result (see app/services/enrichment_service.py)."""

    risk_score: int = Field(..., ge=0, le=100)
    threat_tags: list[str] = Field(default_factory=list)
    mitre_details: list[MitreTechniqueDetail] = Field(default_factory=list)
    attack_timeline: list[str] = Field(default_factory=list)
    explainability: list[ExplainabilityItem] = Field(default_factory=list)
    recommendations_grouped: RecommendationsGrouped
    sigma_match: SigmaMatch
    detection_metrics: DetectionMetrics
    # --- Enterprise SOC additions (additive) ---
    owasp_mappings: list[OwaspMapping] = Field(default_factory=list)
    risk_factors: list[str] = Field(default_factory=list)
    knowledge_sources: list[str] = Field(default_factory=list)
    playbook_actions: list[PlaybookAction] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: str
    input_text: str
    input_type: str
    classification: ThreatClassification
    risk_level: RiskLevel
    confidence: int
    summary: str
    explanation: str
    recommendations: list[str]
    indicators: list[str]
    mitre_techniques: list[str]
    iocs: IOCResult
    model_used: str
    latency_ms: float
    created_at: datetime

    # --- Analyzer page enrichment (additive, may be null for older rows) ---
    risk_score: Optional[int] = None
    threat_tags: Optional[list[str]] = None
    mitre_details: Optional[list[MitreTechniqueDetail]] = None
    attack_timeline: Optional[list[str]] = None
    explainability: Optional[list[ExplainabilityItem]] = None
    recommendations_grouped: Optional[RecommendationsGrouped] = None
    sigma_match: Optional[SigmaMatch] = None
    detection_metrics: Optional[DetectionMetrics] = None
    threat_intel: Optional[ThreatIntelEnrichment] = None
    owasp_mappings: Optional[list[OwaspMapping]] = None
    risk_factors: Optional[list[str]] = None
    knowledge_sources: Optional[list[str]] = None
    playbook_actions: Optional[list[PlaybookAction]] = None


class AnalysisListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    input_type: str
    classification: ThreatClassification
    risk_level: RiskLevel
    confidence: int
    summary: str
    created_at: datetime
    risk_score: Optional[int] = None


class PaginatedAnalyses(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[AnalysisListItem]
