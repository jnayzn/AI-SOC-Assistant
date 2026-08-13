# Analysis Data Model

This document is the canonical reference for how the Analyzer, Dashboard,
History, and PDF/CSV/XLSX exports all derive their numbers from **one**
underlying model: the `Analysis` row (see `app/models/analysis.py`,
`app/schemas/analysis.py`).

Every Dashboard KPI and chart is computed from these stored columns only.
Nothing in the Dashboard is decorative or hardcoded, and nothing in the
Dashboard requires a concept the Analyzer cannot actually produce.

## The four dimensions

An analysis result is described along four independent dimensions. They are
independent on purpose: selecting a Content Type never implies a
Classification, a Classification never implies a Severity, etc.

| # | Dimension | Field | Type | Set by | Example values |
|---|-----------|-------|------|--------|-----------------|
| 1 | **Input / Content Type** | `input_type` | free string, chosen in the Analyzer UI | The user, before analysis | `email` ("Phishing Email"), `soc_alert`, `windows_log`, `linux_log`, `other` |
| 2 | **Classification / Verdict** | `classification` | `ThreatClassification` enum | The LLM's structured output (`LLMAnalysisResult.classification`) | Benign, Spam, Suspicious, Phishing, Malware, Credential Theft, Business Email Compromise, Data Exfiltration, Unknown |
| 3 | **Severity** | `risk_level` | `RiskLevel` enum | The LLM's structured output (`LLMAnalysisResult.risk_level`) | Low, Medium, High, Critical |
| 4 | **Threat Category** | `threat_tags` | `list[str]` (JSON column, nullable) | Deterministically computed server-side in `enrichment_service.build_enrichment()`, from the classification plus evidence-based keyword signals found in the raw text/explanation | Phishing, Social Engineering, Credential Theft, Business Email Compromise, Data Exfiltration, Malware, Brute Force, Suspicious PowerShell, Account Compromise, Network Attack, Typosquatting, Brand Impersonation, Urgency, Malicious Link, Spam, Benign, Unclassified |

`input_type` is never read by any counting/aggregation code. It exists
solely to record what the user submitted; it has no influence on
Classification, Severity, or Threat Category, which are always produced by
analyzing the content.

`threat_tags` is multi-valued (an analysis can be tagged both `"Phishing"`
and `"Credential Theft"`, for example) and is a superset of the top-level
`classification`: it starts from `_CLASSIFICATION_BASE_TAGS[classification]`
and then adds any additional tag whose independent evidence pattern (see
`_EXPLAINABILITY_CHECKLIST` / `_TAG_RULES` in `enrichment_service.py`) is
found in the raw text or explanation -- so a `Suspicious`-classified Windows
log can still legitimately carry a `"Malware"` threat tag if malware-like
indicators (e.g. "ransomware", "dropper", "rootkit") are present, without
requiring the top-level verdict itself to be the literal string `"Malware"`.

## How each Dashboard KPI derives from these fields

| KPI | Source | Notes |
|-----|--------|-------|
| Total Analyses | `COUNT(*)` over `Analysis` | `AnalysisRepository.count_all()` |
| Phishing Detected | `COUNT(*)` where `"Phishing" IN threat_tags` | `AnalysisRepository.count_with_threat_tag("Phishing")` -- a Threat Category count, independent of `input_type`. Selecting "Phishing Email" as Content Type does **not** by itself increment this. |
| Malware Detected | `COUNT(*)` where `"Malware" IN threat_tags` | `AnalysisRepository.count_with_threat_tag("Malware")` -- same pattern, and can now be produced from any input type (SOC alert, Windows/Linux log, free text) once malware evidence is detected. |
| Critical Alerts | `COUNT(*)` where `risk_level = "Critical"` | `AnalysisRepository.count_by_risk("Critical")` -- a pure Severity count, unaffected by classification or content type. |
| Average Risk Score | `AVG(risk_score)` | `AnalysisRepository.average_risk_score()` |
| Average Confidence | `AVG(confidence)` | `AnalysisRepository.average_confidence()` |
| Risk Distribution chart | `GROUP BY risk_level` | `AnalysisRepository.risk_distribution()` |
| Classification Breakdown chart | `GROUP BY classification` | `AnalysisRepository.classification_distribution()` |
| Weekly Statistics chart | Per day: `total` = row count, `critical` = `risk_level = "Critical"` count (SQL), `phishing`/`malware` = `threat_tags` membership count (Python, same rows) | `AnalysisRepository.weekly_stats()` |

All of the above read directly from the same `Analysis` table rows that
History, the Analyzer result view, and PDF/CSV/XLSX exports read from --
there is no separate/duplicated aggregation path.

## Worked examples

- **Windows Event Log, strong malware evidence.** `input_type="windows_log"`,
  `classification="Suspicious"`, `risk_level="Critical"`,
  `threat_tags=["Malware", "Suspicious PowerShell"]` (base tags for
  `Suspicious` are empty, but the "Malware Behavior"/"Suspicious PowerShell"
  evidence patterns matched). This increments **Malware Detected** and
  **Critical Alerts**, but not **Phishing Detected**.
- **Phishing Email content type, but legitimate content.**
  `input_type="email"`, `classification="Benign"`, `risk_level="Low"`,
  `threat_tags=["Benign"]`. This increments none of Phishing/Malware/
  Critical -- selecting "Phishing Email" as Content Type never counts as a
  detection by itself.
- **Confirmed phishing email, High severity.** `input_type="email"`,
  `classification="Phishing"`, `risk_level="High"`,
  `threat_tags=["Phishing", "Social Engineering"]`. Increments **Phishing
  Detected** only (not Critical, since severity is High, not Critical).
