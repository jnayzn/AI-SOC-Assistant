"""Lightweight local knowledge base used to ground the LLM (RAG-lite).

For the full bonus RAG pipeline, app/llm/retriever.py embeds these documents
into ChromaDB and retrieves the top-k most relevant snippets per request
instead of sending the full static list below.
"""
import re

TACTIC_IDS = {
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
}

MITRE_ATTACK_TECHNIQUES = [
    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "description": "Adversaries send phishing messages to gain access to victim systems. Phishing may be targeted (spearphishing) or sent broadly, and typically relies on social engineering to convince a user to click a link, open an attachment, or hand over credentials."},
    {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access", "description": "A specific variant of phishing where a malicious file is attached to the email. The attacker relies on the victim opening the attachment to execute malicious code or macros."},
    {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access", "description": "A specific variant of phishing where a malicious link is embedded in the email, usually pointing to a credential-harvesting page or a site that delivers malware to the victim."},
    {"id": "T1204", "name": "User Execution", "tactic": "Execution", "description": "Adversaries rely on a user taking an action -- opening a file, clicking a link, or running a program -- to achieve code execution as part of the attack chain."},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion / Persistence", "description": "Adversaries use compromised, legitimate credentials to access systems, blending in with normal activity and evading detection that targets malware or unauthorized tools."},
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "description": "Adversaries attempt to systematically guess account credentials via repeated authentication attempts, often automated, until valid credentials are found or the account locks."},
    {"id": "T1539", "name": "Steal Web Session Cookie", "tactic": "Credential Access", "description": "Adversaries steal session cookies to bypass authentication, including MFA, by reusing an already-authenticated web session rather than obtaining raw credentials."},
    {"id": "T1114", "name": "Email Collection", "tactic": "Collection", "description": "Adversaries target victim email to collect sensitive information, often after compromising an account via phishing or credential theft."},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "description": "Adversaries steal data by sending it over an existing command-and-control channel, avoiding the need for a separate exfiltration channel."},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "description": "Adversaries encrypt data on target systems to disrupt availability, typically as part of a ransomware attack demanding payment for decryption."},
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "description": "Adversaries communicate with compromised systems using common application-layer protocols (HTTP/S, DNS, etc.) to blend malicious traffic with legitimate network activity."},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "description": "Adversaries abuse command and script interpreters (PowerShell, bash, etc.) to execute commands, scripts, or binaries as part of gaining or maintaining access."},
    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "description": "Adversaries obscure malicious content -- files, commands, or payloads -- to evade detection by security tools and analysts."},
    {"id": "T1195", "name": "Supply Chain Compromise", "tactic": "Initial Access", "description": "Adversaries compromise a product, update mechanism, or vendor to gain access to downstream victims before any direct compromise of the victim occurs."},
    {"id": "T1534", "name": "Internal Spearphishing", "tactic": "Lateral Movement", "description": "Adversaries use an already-compromised internal account to send phishing messages to other users inside the organization, exploiting implicit trust in internal senders."},
]

MITRE_BY_ID = {t["id"]: t for t in MITRE_ATTACK_TECHNIQUES}

# Ordered tactic list, used to render a complete MITRE ATT&CK Matrix (columns)
# on the frontend, independent of which techniques were actually detected.
MITRE_TACTIC_ORDER = list(TACTIC_IDS.keys())

_TECHNIQUE_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

OWASP_TOP_10_2021 = [
    {"id": "A01:2021", "name": "Broken Access Control"},
    {"id": "A02:2021", "name": "Cryptographic Failures"},
    {"id": "A03:2021", "name": "Injection"},
    {"id": "A04:2021", "name": "Insecure Design"},
    {"id": "A05:2021", "name": "Security Misconfiguration"},
    {"id": "A06:2021", "name": "Vulnerable and Outdated Components"},
    {"id": "A07:2021", "name": "Identification and Authentication Failures"},
    {"id": "A08:2021", "name": "Software and Data Integrity Failures"},
    {"id": "A09:2021", "name": "Security Logging and Monitoring Failures"},
    {"id": "A10:2021", "name": "Server-Side Request Forgery"},
]

OWASP_BY_ID = {o["id"]: o["name"] for o in OWASP_TOP_10_2021}

PHISHING_INDICATOR_CHECKLIST = [
    "Sender domain does not match the claimed organization (lookalike/typosquat domain)",
    "Urgent or threatening language pressuring immediate action",
    "Requests for credentials, MFA codes, or payment/banking details",
    "Mismatched or shortened/obfuscated hyperlink destinations",
    "Unexpected attachment with executable, macro-enabled, or archive extension",
    "Generic greeting instead of the recipient's real name",
    "Poor grammar/spelling inconsistent with claimed sender",
    "Spoofed or look-alike display name vs. reply-to address",
    "Request to bypass normal approval / verification process (common in BEC)",
]


def build_knowledge_context() -> str:
    """Render a compact text block to inject into the LLM system/user prompt."""
    mitre_lines = "\n".join(
        f"- {t['id']} {t['name']} ({t['tactic']})" for t in MITRE_ATTACK_TECHNIQUES
    )
    owasp_lines = "\n".join(f"- {o['id']} {o['name']}" for o in OWASP_TOP_10_2021)
    indicator_lines = "\n".join(f"- {i}" for i in PHISHING_INDICATOR_CHECKLIST)
    return (
        "Relevant MITRE ATT&CK techniques you may cite when applicable:\n"
        f"{mitre_lines}\n\n"
        "Relevant OWASP Top 10 (2021) categories you may cite when applicable:\n"
        f"{owasp_lines}\n\n"
        "Common phishing/BEC indicator checklist:\n"
        f"{indicator_lines}"
    )


def get_mitre_detail(raw: str) -> dict:
    """Enriches a raw LLM-provided MITRE string (e.g. 'T1566.002 Spearphishing Link')
    with tactic id/name and a description, using the local knowledge base as the
    source of truth (does not trust the LLM's own wording for these fields).
    """
    match = _TECHNIQUE_ID_RE.search(raw or "")
    technique_id = match.group(0) if match else None
    known = MITRE_BY_ID.get(technique_id) if technique_id else None

    if known:
        return {
            "id": known["id"],
            "name": known["name"],
            "tactic_id": TACTIC_IDS.get(known["tactic"].split(" / ")[0], "TA0000"),
            "tactic_name": known["tactic"],
            "description": known["description"],
        }

    fallback_name = raw.strip() if raw else "Unclassified technique"
    return {
        "id": technique_id or "N/A",
        "name": fallback_name,
        "tactic_id": "TA0000",
        "tactic_name": "Unknown",
        "description": "No local knowledge base entry matched this technique; shown as reported by the AI model.",
    }
