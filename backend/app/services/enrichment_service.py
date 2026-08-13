"""Deterministic post-processing that enriches the raw LLM analysis result with
additional Analyzer-page data (risk score, threat tags, structured MITRE
details, attack timeline, explainability checklist, grouped recommendations,
a Sigma-style rule match, and cosmetic detection-probability metrics).

These are computed with rules/heuristics rather than asked from the LLM so
they stay reliable even with small local models (e.g. llama3.2:3b) that are
not always consistent at producing rich structured JSON.
"""
from app.llm.knowledge_base import OWASP_BY_ID, get_mitre_detail
from app.schemas.analysis import (
    AnalysisEnrichment,
    DetectionMetrics,
    ExplainabilityItem,
    LLMAnalysisResult,
    MitreTechniqueDetail,
    OwaspMapping,
    PlaybookAction,
    RecommendationsGrouped,
    RiskLevel,
    SigmaMatch,
    ThreatClassification,
)

_MALICIOUS_CLASSIFICATIONS = {
    ThreatClassification.PHISHING,
    ThreatClassification.MALWARE,
    ThreatClassification.CREDENTIAL_THEFT,
    ThreatClassification.BEC,
    ThreatClassification.DATA_EXFILTRATION,
}

_BENIGN_CLASSIFICATIONS = {
    ThreatClassification.BENIGN,
    ThreatClassification.SPAM,
    ThreatClassification.UNKNOWN,
}

_RISK_SCORE_BASE = {
    RiskLevel.LOW: (5, 0.30),
    RiskLevel.MEDIUM: (30, 0.30),
    RiskLevel.HIGH: (55, 0.30),
    RiskLevel.CRITICAL: (75, 0.25),
}

_EXPLAINABILITY_CHECKLIST = [
    ("Lookalike Domain", ["lookalike", "look-alike", "typosquat", "look alike domain"]),
    ("Credential Harvesting", ["credential", "harvest", "login page", "password"]),
    ("Suspicious Language", ["urgent", "threatening", "suspicious language", "poor grammar", "pressure"]),
    ("External Link", ["link", "url", "hyperlink", "http"]),
    ("Urgency", ["urgent", "immediately", "24 hours", "urgency", "act now", "suspend"]),
    ("Brand Impersonation", ["impersonat", "spoofed", "brand", "mimick"]),
    ("Suspicious Sender", ["sender", "spoofed address", "reply-to"]),
    ("Mismatched URL", ["mismatch", "different domain", "destination"]),
    # --- Threat-category signals that are independent of the top-level
    # classification/verdict, so a normalized threat category (see
    # `_TAG_RULES` below) can be detected even when the LLM's classification
    # is a generic verdict like "Suspicious" rather than a specific one. ---
    (
        "Malware Behavior",
        ["malware", "trojan", "ransomware", "backdoor", "payload", "dropper", "worm", "rootkit", "spyware", "keylogger"],
    ),
    (
        "Brute Force Pattern",
        ["brute force", "brute-force", "failed login", "failed logon", "credential stuffing", "password spray"],
    ),
    (
        "Suspicious PowerShell",
        ["powershell", "encoded command", "invoke-expression", "invoke-mimikatz", "-enc ", "iex("],
    ),
    (
        "Account Compromise Indicators",
        ["account takeover", "compromised account", "unauthorized access", "account compromise", "impossible travel"],
    ),
    (
        "Network Attack Pattern",
        ["port scan", "ddos", "lateral movement", "exfiltration over", "c2 traffic", "command and control", "beaconing"],
    ),
]

_TAG_RULES = [
    ("Lookalike Domain", "Typosquatting"),
    ("Credential Harvesting", "Credential Theft"),
    ("Brand Impersonation", "Brand Impersonation"),
    ("Urgency", "Urgency"),
    ("External Link", "Malicious Link"),
    # Normalized Threat Category tags, independent of `classification`. These
    # let the Dashboard derive e.g. "Malware Detected" from a genuine
    # normalized threat-category signal instead of only from an exact-match
    # top-level verdict string (see AnalysisRepository.count_with_threat_tag).
    ("Malware Behavior", "Malware"),
    ("Brute Force Pattern", "Brute Force"),
    ("Suspicious PowerShell", "Suspicious PowerShell"),
    ("Account Compromise Indicators", "Account Compromise"),
    ("Network Attack Pattern", "Network Attack"),
]

_CLASSIFICATION_BASE_TAGS = {
    ThreatClassification.PHISHING: ["Phishing", "Social Engineering"],
    ThreatClassification.CREDENTIAL_THEFT: ["Credential Theft", "Social Engineering"],
    ThreatClassification.BEC: ["Business Email Compromise", "Social Engineering"],
    ThreatClassification.MALWARE: ["Malware"],
    ThreatClassification.DATA_EXFILTRATION: ["Data Exfiltration"],
    ThreatClassification.SUSPICIOUS: ["Suspicious Activity"],
    ThreatClassification.SPAM: ["Spam"],
    ThreatClassification.BENIGN: ["Benign"],
    ThreatClassification.UNKNOWN: ["Unclassified"],
}

_ATTACK_TIMELINES = {
    ThreatClassification.PHISHING: [
        "Email Received",
        "User Opens Email",
        "User Clicks Link",
        "Credential Theft",
        "Attacker Login",
        "Account Compromise",
    ],
    ThreatClassification.CREDENTIAL_THEFT: [
        "Email or Message Received",
        "User Directed to Fake Login Page",
        "Credentials Submitted",
        "Attacker Captures Credentials",
        "Attacker Login",
        "Account Compromise",
    ],
    ThreatClassification.MALWARE: [
        "File or Attachment Delivered",
        "User Executes Payload",
        "Malware Installed",
        "Persistence Established",
        "Command & Control Established",
        "Impact (Data Theft / Encryption)",
    ],
    ThreatClassification.BEC: [
        "Executive Email Spoofed or Compromised",
        "Fraudulent Request Sent to Employee",
        "Employee Acts on Request",
        "Funds or Data Transferred",
        "Fraud Discovered",
    ],
    ThreatClassification.DATA_EXFILTRATION: [
        "Initial Access Gained",
        "Internal Reconnaissance",
        "Sensitive Data Collected",
        "Data Staged",
        "Data Exfiltrated",
    ],
    ThreatClassification.SUSPICIOUS: [
        "Anomalous Activity Detected",
        "Repeated / Unusual Attempts Observed",
        "Possible Compromise if Unaddressed",
        "Escalation if Undetected",
    ],
}

_SIGMA_RULE_NAME = "Credential Harvesting"
_SIGMA_KEYWORDS = ["login", "password", "urgent", "verify"]

# --- OWASP Top 10 (2021) mapping rules -------------------------------------
# Narrative mapping from a matched explainability signal to the OWASP
# category it most resembles conceptually. This is intentionally a SOC
# triage/education aid ("which class of security failure does this incident
# resemble"), not a claim that the analyzed artifact is a web application
# being scanned for vulnerabilities.
_OWASP_RULES: list[tuple[str, str, str]] = [
    (
        "Credential Harvesting",
        "A07:2021",
        "The attack directly targets user authentication credentials.",
    ),
    (
        "Brute Force Pattern",
        "A07:2021",
        "Repeated authentication attempts exploit weak authentication controls.",
    ),
    (
        "Suspicious PowerShell",
        "A03:2021",
        "Interpreter/command abuse resembles injection-style malicious execution.",
    ),
    (
        "Malware Behavior",
        "A08:2021",
        "Malicious payload execution compromises software and data integrity.",
    ),
    (
        "Account Compromise Indicators",
        "A01:2021",
        "Indicates access to an account or resource beyond its intended scope.",
    ),
    (
        "Network Attack Pattern",
        "A09:2021",
        "Command-and-control / exfiltration traffic often evades insufficient logging and monitoring.",
    ),
    (
        "Lookalike Domain",
        "A05:2021",
        "Typosquatted infrastructure exploits weak configuration of trusted domains/links.",
    ),
    (
        "Brand Impersonation",
        "A07:2021",
        "Impersonation exploits weak verification of sender/identity.",
    ),
    (
        "Mismatched URL",
        "A05:2021",
        "Misleading link destinations reflect a security misconfiguration / deceptive routing.",
    ),
]

_RISK_FACTOR_PHRASES: dict[str, str] = {
    "Lookalike Domain": "Lookalike / typosquatted domain detected",
    "Credential Harvesting": "Credential harvesting indicators present",
    "Suspicious Language": "Urgent or pressuring language detected",
    "External Link": "Suspicious external link or URL present",
    "Urgency": "Urgency / pressure tactics detected",
    "Brand Impersonation": "Brand impersonation detected",
    "Suspicious Sender": "Suspicious or spoofed sender address",
    "Mismatched URL": "Mismatched link destination",
    "Malware Behavior": "Malware behavior patterns detected",
    "Brute Force Pattern": "Brute-force authentication pattern detected",
    "Suspicious PowerShell": "Suspicious PowerShell execution detected",
    "Account Compromise Indicators": "Account compromise indicators present",
    "Network Attack Pattern": "Network attack / C2 pattern detected",
}

# --- Automated playbook catalog --------------------------------------------
# Maps a normalized threat_tag to recommended SOC response actions with a
# priority + NIST-style phase category. Deduplicated by action name, keeping
# the highest priority across all matching tags.
_PLAYBOOK_CATALOG: dict[str, list[tuple[str, str, str]]] = {
    "Malware": [
        ("Isolate Host", "Critical", "Containment"),
        ("Run Defender / EDR Scan", "High", "Eradication"),
        ("Collect Memory Image", "High", "Forensics"),
        ("Collect Disk Image", "Medium", "Forensics"),
        ("Verify Persistence Mechanisms", "Medium", "Eradication"),
    ],
    "Phishing": [
        ("Block Sender Domain", "High", "Containment"),
        ("Search SIEM for Similar Messages", "Medium", "Investigation"),
        ("Notify Affected Users", "Medium", "Communication"),
    ],
    "Credential Theft": [
        ("Reset Affected Passwords", "Critical", "Containment"),
        ("Force MFA Re-enrollment", "High", "Containment"),
        ("Disable Compromised User Account", "High", "Containment"),
    ],
    "Business Email Compromise": [
        ("Disable Compromised Mailbox Rules", "High", "Containment"),
        ("Verify Financial Transactions", "Critical", "Investigation"),
    ],
    "Data Exfiltration": [
        ("Isolate Host", "Critical", "Containment"),
        ("Block Outbound IP / Domain", "High", "Containment"),
        ("Investigate Data Access Logs", "High", "Investigation"),
    ],
    "Brute Force": [
        ("Block Source IP", "High", "Containment"),
        ("Enforce Account Lockout / MFA", "Medium", "Containment"),
    ],
    "Suspicious PowerShell": [
        ("Collect Memory Image", "High", "Forensics"),
        ("Verify Persistence Mechanisms", "High", "Eradication"),
    ],
    "Network Attack": [
        ("Block Source / Destination IP", "High", "Containment"),
        ("Search SIEM for Related Traffic", "Medium", "Investigation"),
    ],
    "Account Compromise": [
        ("Disable User Account", "Critical", "Containment"),
        ("Reset Password", "Critical", "Containment"),
        ("Review Account Access Logs", "High", "Investigation"),
    ],
    "Typosquatting": [
        ("Block Domain", "High", "Containment"),
    ],
}

_PRIORITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

# Cues that indicate the text immediately before a matched keyword is negating
# it (e.g. "no malware indicators were observed", "not consistent with
# phishing"). Without this guard, plain substring matching over LLM-written
# prose (summary/explanation) is fragile: an analysis that explicitly rules
# out malware/urgency/etc. would otherwise still get tagged as if it were
# positive evidence, simply because the word appears somewhere in the text.
_NEGATION_CUES = [
    "no ",
    "not ",
    "none ",
    "n't ",
    "without ",
    "never ",
    "lack of ",
    "absence of ",
    "ruled out",
    "unlikely",
    "isn't",
    "wasn't",
    "aren't",
    "weren't",
    "hasn't",
    "haven't",
    "doesn't",
    "didn't",
]
_NEGATION_WINDOW_CHARS = 40


def _matches_any(haystack: str, keywords: list[str]) -> bool:
    """Returns True if any keyword appears in haystack as genuine (non-negated)
    evidence. A keyword match is discarded if a negation cue appears in the
    `_NEGATION_WINDOW_CHARS` characters immediately preceding it, so negated
    mentions ("no malware was found") do not count as positive evidence.
    This is a deliberately simple, deterministic guard -- not full NLP -- but
    it removes the most common false-positive pattern from naive substring
    matching without requiring a model call.
    """
    for keyword in keywords:
        start = 0
        while True:
            idx = haystack.find(keyword, start)
            if idx == -1:
                break
            window = haystack[max(0, idx - _NEGATION_WINDOW_CHARS) : idx]
            if not any(cue in window for cue in _NEGATION_CUES):
                return True
            start = idx + 1
    return False


def _compute_risk_score(risk_level: RiskLevel, confidence: int) -> int:
    base, weight = _RISK_SCORE_BASE[risk_level]
    score = base + round(confidence * weight)
    return max(0, min(100, score))


def _compute_explainability(context_text: str) -> list[ExplainabilityItem]:
    return [
        ExplainabilityItem(label=label, matched=_matches_any(context_text, keywords))
        for label, keywords in _EXPLAINABILITY_CHECKLIST
    ]


def _compute_threat_tags(
    classification: ThreatClassification, explainability: list[ExplainabilityItem]
) -> list[str]:
    tags: list[str] = list(_CLASSIFICATION_BASE_TAGS.get(classification, []))
    matched_labels = {item.label for item in explainability if item.matched}
    for label, tag in _TAG_RULES:
        if label in matched_labels and tag not in tags:
            tags.append(tag)
    return tags


def _compute_mitre_details(mitre_techniques: list[str]) -> list[MitreTechniqueDetail]:
    return [MitreTechniqueDetail(**get_mitre_detail(raw)) for raw in mitre_techniques]


def _compute_attack_timeline(classification: ThreatClassification) -> list[str]:
    return list(_ATTACK_TIMELINES.get(classification, []))


def _compute_sigma_match(raw_text: str) -> SigmaMatch:
    text = raw_text.lower()
    matched_keywords = [kw for kw in _SIGMA_KEYWORDS if kw in text]
    return SigmaMatch(
        rule_name=_SIGMA_RULE_NAME,
        matched=len(matched_keywords) >= 2,
        matched_indicators=matched_keywords,
    )


def _compute_recommendations_grouped(recommendations: list[str]) -> RecommendationsGrouped:
    immediate_kw = ["don't click", "do not click", "block", "do not enter", "avoid", "do not reply"]
    investigate_kw = ["review", "search", "investigate", "correlat", "check logs", "analyze"]
    contain_kw = ["reset", "mfa", "revoke", "quarantine", "isolate", "disable", "lock"]
    recover_kw = ["monitor", "restore", "backup", "recover"]

    groups = RecommendationsGrouped(immediate=[], investigate=[], contain=[], recover=[])
    for rec in recommendations:
        lower = rec.lower()
        if _matches_any(lower, contain_kw):
            groups.contain.append(rec)
        elif _matches_any(lower, recover_kw):
            groups.recover.append(rec)
        elif _matches_any(lower, investigate_kw):
            groups.investigate.append(rec)
        elif _matches_any(lower, immediate_kw):
            groups.immediate.append(rec)
        else:
            groups.immediate.append(rec)
    return groups


def _compute_detection_metrics(classification: ThreatClassification, confidence: int) -> DetectionMetrics:
    confidence = max(0, min(100, confidence))
    if classification in _MALICIOUS_CLASSIFICATIONS:
        malicious = confidence
        suspicious = round((100 - confidence) * 0.5)
        false_positive = max(0, 100 - malicious - suspicious)
    elif classification == ThreatClassification.SUSPICIOUS:
        suspicious = confidence
        malicious = round(confidence * 0.4)
        false_positive = max(0, 100 - suspicious - malicious)
    else:
        false_positive = confidence
        suspicious = max(0, round((100 - confidence) * 0.5))
        malicious = max(0, 100 - false_positive - suspicious)

    return DetectionMetrics(
        detection_confidence=confidence,
        malicious_probability=malicious,
        suspicious_probability=suspicious,
        false_positive_probability=false_positive,
    )


def _compute_owasp_mappings(
    classification: ThreatClassification, explainability: list[ExplainabilityItem]
) -> list[OwaspMapping]:
    matched_labels = {item.label for item in explainability if item.matched}
    seen_ids: set[str] = set()
    mappings: list[OwaspMapping] = []
    for label, owasp_id, reason in _OWASP_RULES:
        if label in matched_labels and owasp_id not in seen_ids:
            mappings.append(OwaspMapping(id=owasp_id, name=OWASP_BY_ID[owasp_id], reason=reason))
            seen_ids.add(owasp_id)
    if classification == ThreatClassification.DATA_EXFILTRATION and "A01:2021" not in seen_ids:
        mappings.append(
            OwaspMapping(
                id="A01:2021",
                name=OWASP_BY_ID["A01:2021"],
                reason="Data exfiltration is unauthorized access to protected data beyond intended access-control boundaries.",
            )
        )
        seen_ids.add("A01:2021")
    return mappings


def _compute_risk_factors(explainability: list[ExplainabilityItem]) -> list[str]:
    return [
        _RISK_FACTOR_PHRASES.get(item.label, item.label)
        for item in explainability
        if item.matched
    ]


def _compute_knowledge_sources(model_used: str | None) -> list[str]:
    sources = [
        "Local MITRE ATT&CK & OWASP Top 10 Knowledge Base",
        "Deterministic Explainability & Risk Scoring Engine",
    ]
    if model_used:
        sources.append(f"LLM Threat Analysis Model ({model_used})")
    return sources


def _compute_playbook_actions(
    threat_tags: list[str], risk_level: RiskLevel
) -> list[PlaybookAction]:
    collected: dict[str, tuple[str, str]] = {}

    def _add(action: str, priority: str, category: str) -> None:
        existing = collected.get(action)
        if existing is None or _PRIORITY_RANK[priority] > _PRIORITY_RANK[existing[0]]:
            collected[action] = (priority, category)

    for tag in threat_tags:
        for action, priority, category in _PLAYBOOK_CATALOG.get(tag, []):
            _add(action, priority, category)

    _add("Investigate Logs", "Medium", "Investigation")
    if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        _add("Notify SOC / Escalate Incident", "Critical", "Communication")
        _add("Search SIEM for Related Activity", "High", "Investigation")

    ordered = sorted(
        collected.items(), key=lambda kv: (-_PRIORITY_RANK[kv[1][0]], kv[0])
    )
    return [
        PlaybookAction(action=action, priority=priority, category=category)
        for action, (priority, category) in ordered
    ]


def build_enrichment(
    raw_text: str, result: LLMAnalysisResult, model_used: str | None = None
) -> AnalysisEnrichment:
    context_text = " ".join(
        [raw_text, result.summary, result.explanation, " ".join(result.indicators)]
    ).lower()

    explainability = _compute_explainability(context_text)
    threat_tags = _compute_threat_tags(result.classification, explainability)

    return AnalysisEnrichment(
        risk_score=_compute_risk_score(result.risk_level, result.confidence),
        threat_tags=threat_tags,
        mitre_details=_compute_mitre_details(result.mitre_techniques),
        attack_timeline=_compute_attack_timeline(result.classification),
        explainability=explainability,
        recommendations_grouped=_compute_recommendations_grouped(result.recommendations),
        sigma_match=_compute_sigma_match(raw_text),
        detection_metrics=_compute_detection_metrics(result.classification, result.confidence),
        owasp_mappings=_compute_owasp_mappings(result.classification, explainability),
        risk_factors=_compute_risk_factors(explainability),
        knowledge_sources=_compute_knowledge_sources(model_used),
        playbook_actions=_compute_playbook_actions(threat_tags, result.risk_level),
    )
