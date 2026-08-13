"""AI SOC Copilot: incident-grounded chat assistant for analysts.

Additive feature. Reuses the same LLM provider configuration as the triage
engine (app.core.config.Settings / LLM_PROVIDER) but talks to the model in
plain conversational mode instead of the strict-JSON triage schema.

The copilot is *grounded* in the security analysis the analyst is currently
looking at: when an ``analysis_id`` is provided we load the authoritative
Analysis record from the database and inject ALL of its relevant fields
(Detailed Explanation, Key Indicators, Explainable-AI signals, MITRE ATT&CK,
IOCs, original analyzed content, verdict/severity/risk score/confidence, ...)
into the model context, and instruct the model to answer strictly from that
incident instead of giving generic cybersecurity lessons. When the record is
not in the DB we fall back to the structured ``incident_context`` object sent
by the frontend so the model still receives the actual analysis.
"""
import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.analysis import Analysis
from app.models.intelowl import IntelOwlScan
from app.schemas.copilot import CopilotChatRequest, CopilotChatResponse

logger = logging.getLogger(__name__)
settings = get_settings()

_MAX_HISTORY_TURNS = 12
_MAX_ORIGINAL_CONTENT_CHARS = 4000

# Strong, incident-specific system instruction. This is intentionally NOT
# surfaced to the end user in the UI (the widget only shows a short
# "grounded in" indicator).
_COPILOT_SYSTEM_PROMPT = (
    "You are an AI SOC Copilot assisting a security analyst inside the Enterprise AI SOC "
    "Assistant platform.\n\n"
    "Your task is to answer questions about the CURRENT security incident displayed in the "
    "application. You MUST ground every answer in the provided incident analysis.\n\n"
    "PRIORITY OF INFORMATION (use higher items before lower ones):\n"
    "1. Detailed Explanation\n"
    "2. Key Indicators\n"
    "3. Explainable AI signals\n"
    "4. MITRE ATT&CK techniques\n"
    "5. Executive Summary\n"
    "6. Verdict / Severity / Risk Score / Confidence\n"
    "7. IntelOwl threat-intelligence enrichment results (real, from the DB)\n"
    "8. Original analyzed content (sender, URLs, domains, IOCs)\n"
    "9. General cybersecurity knowledge\n\n"
    "Always use the incident-specific information before providing general cybersecurity "
    "knowledge. Never provide a generic explanation when the current analysis contains "
    "evidence relevant to the user's question. If the application uses any external "
    "knowledge base, the CURRENT INCIDENT DATA always overrides generic documents.\n\n"
    "When answering an incident-specific question, structure the response as:\n"
    "1. DIRECT ANSWER - specifically for this incident.\n"
    "2. EVIDENCE FROM THIS ANALYSIS - the exact indicators/fields found in the analysis.\n"
    "3. WHY IT MATTERS - the security significance of each indicator.\n"
    "4. CONNECTION TO THE VERDICT - how the evidence supports the verdict and severity.\n"
    "5. MITRE ATT&CK - relevant techniques if available.\n"
    "6. CONCLUSION - a concise incident-specific conclusion.\n"
    "Keep it readable; omit a section if it truly does not apply, but never replace "
    "incident evidence with a generic lecture.\n\n"
    "RULES:\n"
    "- Cite the specific evidence from the current analysis (quote domains, URLs, indicators, "
    "technique IDs exactly as they appear).\n"
    "- Explain why those indicators matter and connect them to the verdict.\n"
    "- Use the MITRE ATT&CK mapping when relevant.\n"
    "- Distinguish between confirmed evidence (present in the analysis) and your inference.\n"
    "- If the analysis does not contain enough information to answer, explicitly say what is "
    "missing. Do NOT invent indicators, domains, URLs, IP addresses, attackers, techniques, "
    "hashes, or any other evidence that is not in the provided analysis.\n"
    "- Cite IntelOwl verdicts, reputation scores and analyzer names only when they "
    "are present in the incident data; never invent IntelOwl results.\n"
    "- Prefer phrasings like 'In this analysis...', 'The Detailed Explanation identifies...', "
    "'The Key Indicator identified is...', 'The verdict is supported by...'. Avoid generic "
    "openers like 'Phishing generally consists of...' or 'Attackers often...'.\n"
    "- Maintain the incident context across the whole conversation: pronouns and short "
    "follow-ups such as 'and the domain?', 'and MITRE?' refer to THIS incident.\n"
    "- Answer in the SAME language the user used (French -> French, English -> English, "
    "Arabic -> Arabic), but keep security terminology (IOC, MITRE ATT&CK, technique IDs like "
    "T1566.002, typosquatting, credential harvesting, spearphishing, Risk Score) as-is.\n\n"
    "You are not a generic cybersecurity chatbot. You are an incident-specific SOC Copilot."
)

# Shown to the model when no incident is in scope, so it does not hallucinate
# an analysis that is not there.
_NO_INCIDENT_BLOCK = (
    "--- Incident context ---\n"
    "No specific security analysis is currently in scope (the analyst is not viewing an "
    "analysis, or the record could not be loaded). If the user's question is about 'this' "
    "incident/email/alert, explain that no analysis is currently loaded and ask them to open "
    "one. You may still answer clearly general SOC questions.\n"
    "--- End incident context ---"
)


def _build_llm() -> ChatOpenAI:
    provider = settings.LLM_PROVIDER.lower()
    if provider == "ollama":
        return ChatOpenAI(
            model=settings.OLLAMA_MODEL,
            temperature=0.2,
            api_key="ollama",
            base_url=settings.OLLAMA_BASE_URL,
        )
    return ChatOpenAI(
        model=settings.OPENAI_MODEL,
        temperature=0.2,
        api_key=settings.OPENAI_API_KEY,
    )


def _clean_list(value: Any) -> list[str]:
    if not value:
        return []
    return [str(v).strip() for v in value if str(v).strip()]


def _analysis_context_block(analysis: Analysis) -> str:
    """Render a rich, priority-ordered text view of an existing Analysis record
    so the copilot can ground its answer in the real data already computed by
    the triage engine, without re-running any AI classification.

    Ordering mirrors the system-prompt PRIORITY OF INFORMATION so the most
    decision-relevant evidence (Detailed Explanation, Key Indicators, ...) is
    the most salient.
    """
    lines: list[str] = [
        "--- CURRENT INCIDENT ANALYSIS (authoritative; ground every answer in this) ---",
        f"Analysis ID: {analysis.id}",
    ]

    # 1. Detailed Explanation (most important).
    if analysis.explanation:
        lines.append("")
        lines.append("[Detailed Explanation]")
        lines.append(analysis.explanation.strip())

    # 2. Key Indicators.
    indicators = _clean_list(analysis.indicators)
    if indicators:
        lines.append("")
        lines.append("[Key Indicators]")
        lines.extend(f"- {i}" for i in indicators)

    # 3. Explainable AI signals.
    if analysis.explainability:
        matched = [e for e in analysis.explainability if isinstance(e, dict) and e.get("matched")]
        not_matched = [
            e for e in analysis.explainability if isinstance(e, dict) and not e.get("matched")
        ]
        lines.append("")
        lines.append("[Explainable AI signals]")
        if matched:
            lines.append("Triggered: " + ", ".join(str(e.get("label", "")) for e in matched))
        if not_matched:
            lines.append(
                "Not triggered: " + ", ".join(str(e.get("label", "")) for e in not_matched)
            )

    # 4. MITRE ATT&CK techniques (prefer enriched details when available).
    if analysis.mitre_details:
        lines.append("")
        lines.append("[MITRE ATT&CK techniques]")
        for m in analysis.mitre_details:
            if not isinstance(m, dict):
                continue
            tactic = m.get("tactic_name") or m.get("tactic_id") or ""
            tactic_suffix = f" (tactic: {tactic})" if tactic else ""
            lines.append(f"- {m.get('id', '')} {m.get('name', '')}{tactic_suffix}")
    elif analysis.mitre_techniques:
        lines.append("")
        lines.append("[MITRE ATT&CK techniques]")
        lines.append(", ".join(_clean_list(analysis.mitre_techniques)))

    # 5. Executive Summary.
    if analysis.summary:
        lines.append("")
        lines.append("[Executive Summary]")
        lines.append(analysis.summary.strip())

    # 6. Verdict / Severity / Risk Score / Confidence + Threat categories.
    lines.append("")
    lines.append("[Verdict / Severity / Scores]")
    lines.append(f"Verdict (classification): {analysis.classification}")
    lines.append(f"Severity (risk level): {analysis.risk_level}")
    if analysis.risk_score is not None:
        lines.append(f"Risk Score: {analysis.risk_score}/100")
    lines.append(f"Confidence: {analysis.confidence}%")
    threat_tags = _clean_list(analysis.threat_tags)
    if threat_tags:
        lines.append("Threat categories: " + ", ".join(threat_tags))
    risk_factors = _clean_list(analysis.risk_factors)
    if risk_factors:
        lines.append("Risk factors: " + ", ".join(risk_factors))
    if isinstance(analysis.detection_metrics, dict) and analysis.detection_metrics:
        dm = analysis.detection_metrics
        lines.append(
            "Detection metrics: "
            f"detection_confidence={dm.get('detection_confidence')}, "
            f"malicious_probability={dm.get('malicious_probability')}, "
            f"suspicious_probability={dm.get('suspicious_probability')}, "
            f"false_positive_probability={dm.get('false_positive_probability')}"
        )

    # OWASP mappings (narrative context).
    if analysis.owasp_mappings:
        owasp_labels = [
            f"{m.get('id')} {m.get('name')}"
            for m in analysis.owasp_mappings
            if isinstance(m, dict)
        ]
        if owasp_labels:
            lines.append("OWASP mappings: " + ", ".join(owasp_labels))

    # 7. IOCs + original analyzed content.
    if isinstance(analysis.iocs, dict) and analysis.iocs:
        ioc_lines = []
        for key in ("ips", "domains", "urls", "emails", "hashes"):
            values = _clean_list(analysis.iocs.get(key))
            if values:
                ioc_lines.append(f"{key}: {', '.join(values)}")
        if ioc_lines:
            lines.append("")
            lines.append("[Indicators of Compromise (IOCs)]")
            lines.extend(ioc_lines)
            emails = _clean_list(analysis.iocs.get("emails"))
            if emails:
                lines.append(
                    "Note: the email address(es) above may include the sender; confirm against "
                    "the original content below rather than assuming."
                )

    # Recommended playbook actions (fixes earlier title/action mismatch).
    if analysis.playbook_actions:
        action_labels = []
        for a in analysis.playbook_actions:
            if not isinstance(a, dict):
                continue
            label = a.get("action") or a.get("title") or ""
            priority = a.get("priority")
            action_labels.append(f"{label} [{priority}]" if priority else label)
        action_labels = [a for a in action_labels if a]
        if action_labels:
            lines.append("")
            lines.append("[Recommended playbook actions]")
            lines.extend(f"- {a}" for a in action_labels)

    if analysis.input_text:
        original = analysis.input_text.strip()
        truncated = original[:_MAX_ORIGINAL_CONTENT_CHARS]
        if len(original) > _MAX_ORIGINAL_CONTENT_CHARS:
            truncated += "\n...[truncated]..."
        lines.append("")
        lines.append("[Original analyzed content]")
        lines.append(truncated)

    lines.append("")
    lines.append("--- End current incident analysis ---")
    return "\n".join(lines)


def _incident_context_block(ctx: dict[str, Any]) -> str:
    """Fallback renderer for the structured incident_context object sent by the
    frontend, used when the analysis record is not available in the database
    (e.g. an analysis that was not persisted). Renders known keys in priority
    order and ignores empty values."""
    if not isinstance(ctx, dict) or not ctx:
        return ""

    def _get(*keys: str) -> Any:
        for k in keys:
            if k in ctx and ctx[k] not in (None, "", [], {}):
                return ctx[k]
        return None

    def _as_lines(value: Any) -> list[str]:
        if isinstance(value, (list, tuple)):
            out = []
            for item in value:
                if isinstance(item, dict):
                    out.append(
                        ", ".join(f"{k}={v}" for k, v in item.items() if v not in (None, ""))
                    )
                elif str(item).strip():
                    out.append(str(item).strip())
            return out
        if isinstance(value, dict):
            return [f"{k}: {v}" for k, v in value.items() if v not in (None, "", [], {})]
        return [str(value).strip()] if str(value).strip() else []

    lines: list[str] = [
        "--- CURRENT INCIDENT ANALYSIS (from the screen; ground every answer in this) ---",
    ]
    sections = [
        ("Detailed Explanation", _get("detailedExplanation", "detailed_explanation", "explanation")),
        ("Key Indicators", _get("keyIndicators", "key_indicators", "indicators")),
        ("Explainable AI signals", _get("explainableSignals", "explainable_signals", "explainability")),
        ("MITRE ATT&CK techniques", _get("mitreTechniques", "mitre_techniques", "mitre_details")),
        ("Executive Summary", _get("executiveSummary", "executive_summary", "summary")),
        ("Verdict", _get("verdict", "classification")),
        ("Severity", _get("severity", "risk_level", "riskLevel")),
        ("Risk Score", _get("riskScore", "risk_score")),
        ("Confidence", _get("confidence")),
        ("Threat categories", _get("threatCategories", "threat_tags", "threat_categories")),
        ("IOCs", _get("iocs")),
        ("URLs", _get("urls")),
        ("Domains", _get("domains")),
        ("Sender", _get("sender")),
        ("Original analyzed content", _get("originalContent", "original_content", "input_text")),
    ]
    for title, value in sections:
        rendered = _as_lines(value)
        if not rendered:
            continue
        lines.append("")
        lines.append(f"[{title}]")
        lines.extend(rendered if len(rendered) > 1 else [rendered[0]])
    lines.append("")
    lines.append("--- End current incident analysis ---")
    return "\n".join(lines)


class CopilotService:
    def __init__(self, db: Session):
        self.db = db

    def _intelowl_context_block(self, analysis_id) -> str:
        """Render REAL IntelOwl enrichment results for this incident from the DB.

        Never fabricates data: with no IntelOwl scans for the analysis the block
        is empty and the copilot simply has no extra evidence to cite.
        """
        if not analysis_id:
            return ""
        rows = (
            self.db.execute(
                select(IntelOwlScan)
                .where(IntelOwlScan.analysis_id == analysis_id)
                .order_by(IntelOwlScan.created_at.asc())
            )
            .scalars()
            .all()
        )
        if not rows:
            return ""
        lines = ["--- IntelOwl Threat Intelligence (real enrichment results) ---"]
        for r in rows:
            line = f"- {r.observable_type}:{r.observable} status={r.status}"
            if r.verdict:
                line += f" verdict={r.verdict}"
            norm = r.normalized_result if isinstance(r.normalized_result, dict) else {}
            rep = norm.get("reputation") or {}
            if isinstance(rep, dict) and rep.get("score") is not None:
                line += f" score={rep.get('score')}"
            analyzers = norm.get("analyzers") or []
            names = [a.get("name") for a in analyzers if isinstance(a, dict) and a.get("name")]
            if names:
                line += f" analyzers={','.join(names)}"
            lines.append(line)
        lines.append("--- End IntelOwl Threat Intelligence ---")
        return "\n".join(lines)

    def chat(self, payload: CopilotChatRequest) -> CopilotChatResponse:
        messages: list = [SystemMessage(content=_COPILOT_SYSTEM_PROMPT)]

        grounded_id = None
        context_block = None

        # Prefer the authoritative DB record when we can resolve the id.
        if payload.analysis_id:
            analysis = self.db.get(Analysis, payload.analysis_id)
            if analysis is not None:
                context_block = _analysis_context_block(analysis)
                grounded_id = analysis.id

        # Fall back to the structured context object supplied by the frontend.
        if context_block is None and payload.incident_context:
            context_block = _incident_context_block(payload.incident_context)
            grounded_id = payload.analysis_id

        # Ground the copilot in REAL IntelOwl enrichment results (from the DB).
        intelowl_block = self._intelowl_context_block(grounded_id)
        if intelowl_block:
            context_block = f"{context_block or _NO_INCIDENT_BLOCK}\n\n{intelowl_block}"

        messages.append(SystemMessage(content=context_block or _NO_INCIDENT_BLOCK))

        for turn in payload.history[-_MAX_HISTORY_TURNS:]:
            if turn.role == "assistant":
                messages.append(AIMessage(content=turn.content))
            else:
                messages.append(HumanMessage(content=turn.content))

        messages.append(HumanMessage(content=payload.message))

        llm = _build_llm()
        response = llm.invoke(messages)
        reply = response.content if isinstance(response.content, str) else str(response.content)

        return CopilotChatResponse(reply=reply, grounded_in_analysis_id=grounded_id)
