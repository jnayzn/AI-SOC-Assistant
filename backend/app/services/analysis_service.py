"""Core orchestration service: sanitize -> LLM analyze -> enrich -> IOC extraction -> persist."""
import logging

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.llm.client import TriageLLMClient, get_llm_client
from app.models.analysis import Analysis
from app.repositories.analysis_repository import AnalysisRepository
from app.schemas.analysis import AnalyzeRequest, IOCResult
from app.services.enrichment_service import build_enrichment
from app.services.ioc_service import extract_iocs
from app.services.notification_service import notify_if_critical
from app.services.threat_intel_service import enrich_with_threat_intel
from app.utils.sanitization import guard_against_injection, sanitize_input

logger = logging.getLogger(__name__)


class AnalysisService:
    def __init__(self, db: Session, llm_client: TriageLLMClient | None = None):
        self.db = db
        self.repo = AnalysisRepository(db)
        self.llm_client = llm_client or get_llm_client()

    def analyze(self, request: AnalyzeRequest, user_id: str | None = None) -> Analysis:
        clean_text = sanitize_input(request.content)
        injection_matches = guard_against_injection(clean_text, block=False)
        if injection_matches:
            logger.warning("Prompt-injection heuristics matched: %s", injection_matches)

        result, latency_ms = self.llm_client.analyze(clean_text, request.input_type or "unknown")
        iocs: IOCResult = extract_iocs(clean_text)
        enrichment = build_enrichment(clean_text, result, model_used=self.llm_client.model)
        threat_intel = enrich_with_threat_intel(iocs)
        # Record which live threat-intel providers actually contributed to
        # this analysis, alongside the always-present local KB/model sources.
        if threat_intel.virustotal_configured:
            enrichment.knowledge_sources.append("VirusTotal Threat Intelligence")
        if threat_intel.shodan_configured:
            enrichment.knowledge_sources.append("Shodan Host Intelligence")
        if threat_intel.abuseipdb_configured:
            enrichment.knowledge_sources.append("AbuseIPDB Reputation Database")

        analysis = Analysis(
            user_id=user_id,
            input_text=clean_text,
            input_type=request.input_type or "unknown",
            classification=result.classification.value,
            risk_level=result.risk_level.value,
            confidence=result.confidence,
            summary=result.summary,
            explanation=result.explanation,
            recommendations=result.recommendations,
            indicators=result.indicators,
            mitre_techniques=result.mitre_techniques,
            iocs=iocs.model_dump(),
            model_used=self.llm_client.model,
            latency_ms=latency_ms,
            risk_score=enrichment.risk_score,
            threat_tags=enrichment.threat_tags,
            mitre_details=[m.model_dump() for m in enrichment.mitre_details],
            attack_timeline=enrichment.attack_timeline,
            explainability=[e.model_dump() for e in enrichment.explainability],
            recommendations_grouped=enrichment.recommendations_grouped.model_dump(),
            sigma_match=enrichment.sigma_match.model_dump(),
            detection_metrics=enrichment.detection_metrics.model_dump(),
            threat_intel=threat_intel.model_dump(mode="json"),
            owasp_mappings=[m.model_dump() for m in enrichment.owasp_mappings],
            risk_factors=enrichment.risk_factors,
            knowledge_sources=enrichment.knowledge_sources,
            playbook_actions=[p.model_dump() for p in enrichment.playbook_actions],
        )
        created = self.repo.create(analysis)
        notify_if_critical(created)
        return created

    def get_or_404(self, analysis_id: str) -> Analysis:
        analysis = self.repo.get_by_id(analysis_id)
        if not analysis:
            raise NotFoundError(f"Analysis '{analysis_id}' not found.")
        return analysis

    def delete(self, analysis_id: str) -> None:
        analysis = self.get_or_404(analysis_id)
        self.repo.delete(analysis)

    def list_paginated(
        self,
        page: int,
        page_size: int,
        classification: str | None,
        risk_level: str | None,
        search: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ):
        return self.repo.list_paginated(
            page=page,
            page_size=page_size,
            classification=classification,
            risk_level=risk_level,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    def list_all_matching(self, classification: str | None, risk_level: str | None, search: str | None = None):
        return self.repo.list_all_matching(classification=classification, risk_level=risk_level, search=search)
