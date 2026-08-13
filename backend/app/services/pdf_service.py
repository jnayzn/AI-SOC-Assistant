"""Generates a downloadable, professional PDF report for a single analysis.

Pagination design notes (remediation pass):
- Uses a custom NumberedCanvas so every page gets a consistent footer with a
  "Page X of Y" indicator, which requires a two-pass render (ReportLab does
  not know the final page count until the whole story has been laid out).
- Section headings are wrapped together with their first piece of content via
  KeepTogether so a heading can never be orphaned alone at the bottom of a
  page. If the heading+content block does not fit in the remaining space on
  the current page, ReportLab moves the whole block to the next page; if it
  still does not fit on a full fresh page, ReportLab falls back to splitting
  the trailing flowable (e.g. a long table/paragraph) while keeping the
  heading attached to the first rendered part.
- Tables use repeatRows=1 so the header row reprints on every continuation
  page if a table has to split.
"""
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    KeepTogether,
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.analysis import Analysis

_RISK_COLORS = {
    "Low": colors.HexColor("#16a34a"),
    "Medium": colors.HexColor("#ca8a04"),
    "High": colors.HexColor("#ea580c"),
    "Critical": colors.HexColor("#dc2626"),
}

_PAGE_W, _PAGE_H = letter
_MARGIN = 0.65 * inch
_TOP_MARGIN = 0.85 * inch
_BOTTOM_MARGIN = 0.8 * inch
_DOC_TITLE = "AI-Powered Security Triage Assistant"
_TABLE_GRID_COLOR = colors.HexColor("#cbd5e1")
_TABLE_HEADER_BG = colors.HexColor("#1e3a8a")


class NumberedCanvas(pdfcanvas.Canvas):
    """Canvas that draws a running header/footer with 'Page X of Y'.

    ReportLab flows content before it knows the final page count, so this
    buffers each page and re-plays it once the total is known (standard
    two-pass technique for accurate page numbering).
    """

    def __init__(self, *args, **kwargs):
        pdfcanvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_footer(total_pages)
            self._draw_header(total_pages)
            pdfcanvas.Canvas.showPage(self)
        pdfcanvas.Canvas.save(self)

    def _draw_footer(self, total_pages):
        self.saveState()
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(_MARGIN, _BOTTOM_MARGIN - 0.15 * inch, _PAGE_W - _MARGIN, _BOTTOM_MARGIN - 0.15 * inch)
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#94a3b8"))
        self.drawString(_MARGIN, _BOTTOM_MARGIN - 0.32 * inch, f"{_DOC_TITLE} \u2014 Confidential Threat Analysis Report")
        self.drawRightString(
            _PAGE_W - _MARGIN, _BOTTOM_MARGIN - 0.32 * inch, f"Page {self._pageNumber} of {total_pages}"
        )
        self.restoreState()

    def _draw_header(self, total_pages):
        if self._pageNumber == 1:
            return
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#1e3a8a"))
        self.drawString(_MARGIN, _PAGE_H - _TOP_MARGIN + 0.32 * inch, _DOC_TITLE)
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#94a3b8"))
        self.drawRightString(_PAGE_W - _MARGIN, _PAGE_H - _TOP_MARGIN + 0.32 * inch, "Threat Analysis Report")
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(_MARGIN, _PAGE_H - _TOP_MARGIN + 0.2 * inch, _PAGE_W - _MARGIN, _PAGE_H - _TOP_MARGIN + 0.2 * inch)
        self.restoreState()


def _table_style(header_bg=_TABLE_HEADER_BG, header_fg=colors.white):
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), header_bg),
            ("TEXTCOLOR", (0, 0), (-1, 0), header_fg),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, _TABLE_GRID_COLOR),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]
    )


def _heading_with_block(heading_style, title, block):
    """Keep a section heading glued to its first content block.

    Prevents the heading from being orphaned alone at the bottom of a page.
    """
    return KeepTogether([Paragraph(title, heading_style), block])


def _bulleted(items, body_style):
    return ListFlowable(
        [ListItem(Paragraph(i, body_style), bulletColor=colors.HexColor("#1e3a8a")) for i in items],
        bulletType="bullet",
        leftIndent=14,
    )


def _section(story, heading_style, styles, title, items):
    """Render a heading + bullet list section, keeping the heading glued to
    the list so it cannot be orphaned; the list itself may still paginate
    naturally across pages if it is long."""
    if not items:
        return
    bullet_list = _bulleted(items, styles["BodyText"])
    story.append(_heading_with_block(heading_style, title, bullet_list))
    story.append(Spacer(1, 12))


_PLAYBOOK_PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _business_impact_narrative(analysis: Analysis) -> str:
    """Deterministic Business Impact paragraph derived from the existing risk
    level, classification, and threat tags -- no new required fields, so this
    stays compatible with analyses generated before this report section was
    added."""
    risk_level = analysis.risk_level or "Unknown"
    classification = analysis.classification or "Unclassified"
    tags = ", ".join(analysis.threat_tags) if analysis.threat_tags else "no additional threat tags"
    impact_by_risk = {
        "Critical": "severe operational disruption, potential data loss, and regulatory/compliance exposure if not contained immediately",
        "High": "significant risk of lateral spread, credential compromise, or data exposure if remediation is delayed",
        "Medium": "moderate risk to affected systems or accounts, with limited but real potential for escalation",
        "Low": "minimal expected impact, though the finding should still be tracked and validated",
    }
    impact = impact_by_risk.get(risk_level, "undetermined impact pending further investigation")
    return (
        f"This {risk_level}-severity {classification} incident carries {impact}. "
        f"Associated threat indicators: {tags}. Business stakeholders and system owners of the affected "
        "assets should be informed in line with the organization's incident response and communication plan."
    )


def _playbook_actions_by_category(analysis: Analysis) -> dict:
    grouped: dict[str, list[dict]] = {}
    for action in analysis.playbook_actions or []:
        grouped.setdefault(action.get("category", "Other"), []).append(action)
    for actions in grouped.values():
        actions.sort(key=lambda a: _PLAYBOOK_PRIORITY_ORDER.get(a.get("priority"), 9))
    return grouped


def _lessons_learned_bullets(analysis: Analysis) -> list:
    bullets = []
    if analysis.risk_factors:
        bullets.append(
            "Review detection coverage for the contributing risk factors identified in this analysis so similar "
            "activity is caught earlier in future incidents."
        )
    if analysis.owasp_mappings:
        bullets.append(
            "Evaluate whether the mapped OWASP categories indicate a broader application or process weakness "
            "that should be addressed beyond this single incident."
        )
    if (analysis.threat_intel or {}).get("local_findings"):
        bullets.append(
            "Threat intelligence API keys were not available for all indicators; consider provisioning "
            "VirusTotal/Shodan/AbuseIPDB access to enrich future investigations beyond local heuristics."
        )
    bullets.append(
        "Confirm the automated playbook actions above were executed and documented, and update runbooks if any "
        "manual step was required that is not yet automated."
    )
    return bullets


def generate_analysis_pdf(analysis: Analysis) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=_TOP_MARGIN,
        bottomMargin=_BOTTOM_MARGIN,
        leftMargin=_MARGIN,
        rightMargin=_MARGIN,
        title=f"{_DOC_TITLE} - Analysis Report",
    )
    styles = getSampleStyleSheet()
    styles["BodyText"].spaceAfter = 4
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], textColor=colors.HexColor("#1e3a8a"))
    heading_style = ParagraphStyle(
        "HeadingStyle", parent=styles["Heading2"], textColor=colors.HexColor("#1e3a8a"), spaceAfter=6, keepWithNext=True
    )
    subtle_style = ParagraphStyle("SubtleStyle", parent=styles["BodyText"], textColor=colors.HexColor("#64748b"))

    story = [
        Paragraph(_DOC_TITLE, title_style),
        Paragraph("Threat Analysis Report", styles["Heading3"]),
        Spacer(1, 12),
    ]

    risk_color = _RISK_COLORS.get(analysis.risk_level, colors.black)
    meta_rows = [
        ["Incident ID", analysis.id],
        ["Classification", analysis.classification],
        ["Risk Level", analysis.risk_level],
        ["Confidence", f"{analysis.confidence}%"],
    ]
    if analysis.risk_score is not None:
        meta_rows.append(["Risk Score", f"{analysis.risk_score}/100"])
    meta_rows += [
        ["Analyzed At", analysis.created_at.strftime("%Y-%m-%d %H:%M UTC")],
        ["Model", analysis.model_used],
        ["Analysis Duration", f"{analysis.latency_ms / 1000:.1f}s"],
    ]
    meta_table = Table(meta_rows, colWidths=[150, 300])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eff6ff")),
                ("TEXTCOLOR", (1, 2), (1, 2), risk_color),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, _TABLE_GRID_COLOR),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    # Small, fixed-size table: always keep it in one piece.
    story.append(KeepTogether([meta_table]))
    story.append(Spacer(1, 16))

    if analysis.threat_tags:
        story.append(Paragraph("Threat Tags: " + ", ".join(analysis.threat_tags), subtle_style))
        story.append(Spacer(1, 10))

    story.append(_heading_with_block(heading_style, "Executive Summary", Paragraph(analysis.summary, styles["BodyText"])))
    story.append(Spacer(1, 12))

    story.append(
        _heading_with_block(heading_style, "Detailed Explanation", Paragraph(analysis.explanation, styles["BodyText"]))
    )
    story.append(Spacer(1, 12))

    _section(story, heading_style, styles, "Indicators", analysis.indicators)

    if analysis.explainability:
        matched = [item["label"] for item in analysis.explainability if item.get("matched")]
        _section(story, heading_style, styles, "Explainable AI Signals Matched", matched or ["None matched"])

    if analysis.risk_factors:
        _section(story, heading_style, styles, "Risk Factors", analysis.risk_factors)

    if analysis.owasp_mappings:
        owasp_rows = [["OWASP ID", "Category", "Reason"]]
        for mapping in analysis.owasp_mappings:
            owasp_rows.append(
                [
                    Paragraph(mapping["id"], styles["BodyText"]),
                    Paragraph(mapping["name"], styles["BodyText"]),
                    Paragraph(mapping["reason"], styles["BodyText"]),
                ]
            )
        owasp_table = Table(owasp_rows, colWidths=[70, 160, 220], repeatRows=1)
        owasp_table.setStyle(_table_style())
        story.append(_heading_with_block(heading_style, "OWASP Top 10 Mapping", owasp_table))
        story.append(Spacer(1, 12))

    if analysis.mitre_details:
        mitre_rows = [["ID", "Technique", "Tactic"]]
        for t in analysis.mitre_details:
            mitre_rows.append(
                [
                    Paragraph(t["id"], styles["BodyText"]),
                    Paragraph(t["name"], styles["BodyText"]),
                    Paragraph(f'{t["tactic_id"]} - {t["tactic_name"]}', styles["BodyText"]),
                ]
            )
        mitre_table = Table(mitre_rows, colWidths=[70, 210, 170], repeatRows=1)
        mitre_table.setStyle(_table_style())
        story.append(_heading_with_block(heading_style, "MITRE ATT&CK Techniques", mitre_table))
        story.append(Spacer(1, 12))
    elif analysis.mitre_techniques:
        _section(story, heading_style, styles, "MITRE ATT&CK Techniques", analysis.mitre_techniques)

    if analysis.attack_timeline:
        timeline_list = ListFlowable(
            [ListItem(Paragraph(f"{i + 1}. {step}", styles["BodyText"])) for i, step in enumerate(analysis.attack_timeline)],
            bulletType="bullet",
            leftIndent=14,
        )
        story.append(_heading_with_block(heading_style, "Attack Timeline", timeline_list))
        story.append(Spacer(1, 12))

    iocs = analysis.iocs or {}
    ioc_rows = []
    for label, key in [("IP", "ips"), ("Domain", "domains"), ("URL", "urls"), ("Email", "emails"), ("Hash", "hashes")]:
        for value in iocs.get(key, []):
            ioc_rows.append([label, Paragraph(value, styles["BodyText"])])
    if ioc_rows:
        ioc_table = Table(
            [["Type", "Value"]] + [[label, value] for label, value in ioc_rows], colWidths=[80, 370], repeatRows=1
        )
        ioc_table.setStyle(_table_style())
        story.append(_heading_with_block(heading_style, "Extracted Indicators of Compromise (IOCs)", ioc_table))
        story.append(Spacer(1, 12))

    threat_intel = analysis.threat_intel or {}
    ti_findings = threat_intel.get("findings") or []
    if ti_findings:
        ti_rows = []
        for finding in ti_findings:
            detail = finding.get("summary") or ""
            if finding.get("error"):
                detail = f"Error: {finding['error']}"
            ti_rows.append(
                [
                    finding.get("source", ""),
                    finding.get("indicator", ""),
                    finding.get("verdict", "Unknown"),
                    Paragraph(detail, styles["BodyText"]),
                ]
            )
        ti_table = Table(
            [["Source", "Indicator", "Verdict", "Details"]] + ti_rows,
            colWidths=[75, 110, 75, 190],
            repeatRows=1,
        )
        ti_table.setStyle(_table_style())
        story.append(_heading_with_block(heading_style, "Threat Intelligence (VirusTotal / Shodan / AbuseIPDB)", ti_table))
        story.append(Spacer(1, 12))
    elif threat_intel.get("virustotal_configured") or threat_intel.get("shodan_configured") or threat_intel.get("abuseipdb_configured"):
        ti_para = Paragraph(
            "Threat intelligence lookups were configured for this analysis but no indicators were resolved.",
            subtle_style,
        )
        story.append(KeepTogether([ti_para]))
        story.append(Spacer(1, 10))

    if analysis.recommendations_grouped:
        group_labels = [
            ("immediate", "Immediate Actions"),
            ("investigate", "Investigate"),
            ("contain", "Contain"),
            ("recover", "Recover"),
        ]
        for key, label in group_labels:
            _section(story, heading_style, styles, label, analysis.recommendations_grouped.get(key, []))
    elif analysis.recommendations:
        _section(story, heading_style, styles, "Recommended Actions", analysis.recommendations)

    playbook_by_category = _playbook_actions_by_category(analysis)
    if playbook_by_category:
        playbook_rows = [["Action", "Priority", "Category"]]
        for category in ["Containment", "Eradication", "Forensics", "Investigation", "Communication", "Other"]:
            for action in playbook_by_category.get(category, []):
                playbook_rows.append(
                    [
                        Paragraph(action["action"], styles["BodyText"]),
                        Paragraph(action["priority"], styles["BodyText"]),
                        Paragraph(action["category"], styles["BodyText"]),
                    ]
                )
        playbook_table = Table(playbook_rows, colWidths=[240, 90, 120], repeatRows=1)
        playbook_table.setStyle(_table_style())
        story.append(_heading_with_block(heading_style, "Automated Playbook Actions", playbook_table))
        story.append(Spacer(1, 12))

    story.append(
        _heading_with_block(
            heading_style, "Business Impact", Paragraph(_business_impact_narrative(analysis), styles["BodyText"])
        )
    )
    story.append(Spacer(1, 12))

    containment_items = [a["action"] for a in playbook_by_category.get("Containment", [])] or (
        analysis.recommendations_grouped or {}
    ).get("contain", [])
    _section(story, heading_style, styles, "Containment", containment_items or ["No containment actions identified."])

    eradication_items = [a["action"] for a in playbook_by_category.get("Eradication", [])] or [
        a["action"] for a in playbook_by_category.get("Forensics", [])
    ]
    _section(story, heading_style, styles, "Eradication", eradication_items or ["No eradication actions identified."])

    recovery_items = (analysis.recommendations_grouped or {}).get("recover", []) or [
        a["action"] for a in playbook_by_category.get("Investigation", [])
    ]
    _section(story, heading_style, styles, "Recovery", recovery_items or ["No recovery actions identified."])

    _section(story, heading_style, styles, "Lessons Learned", _lessons_learned_bullets(analysis))

    if analysis.sigma_match:
        sm = analysis.sigma_match
        status = "MATCHED" if sm.get("matched") else "No Match"
        sigma_para = Paragraph(f"Sigma Rule Match: {sm.get('rule_name')} - {status}", subtle_style)
        story.append(KeepTogether([sigma_para]))
        story.append(Spacer(1, 10))

    if analysis.detection_metrics:
        dm = analysis.detection_metrics
        dm_table = Table(
            [
                ["Detection Confidence", "Malicious Probability", "Suspicious Probability", "False Positive Probability"],
                [
                    f"{dm.get('detection_confidence', 0)}%",
                    f"{dm.get('malicious_probability', 0)}%",
                    f"{dm.get('suspicious_probability', 0)}%",
                    f"{dm.get('false_positive_probability', 0)}%",
                ],
            ],
            colWidths=[112, 112, 113, 113],
        )
        dm_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eff6ff")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, _TABLE_GRID_COLOR),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(_heading_with_block(heading_style, "Detection Metrics", dm_table))
        story.append(Spacer(1, 12))

    truncated = analysis.input_text[:2000] + ("..." if len(analysis.input_text) > 2000 else "")
    original_input_para = Paragraph(truncated.replace("\n", "<br/>"), styles["Code"])
    story.append(_heading_with_block(heading_style, "Original Input (truncated)", original_input_para))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
