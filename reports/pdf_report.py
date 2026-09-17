import json
import os
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from database.models import Scan


def _extract_recon_pdf(scan: Scan) -> Optional[Dict[str, Any]]:
    """Extract passive recon data from scan.response_headers['_recon'], or None."""
    if not scan.response_headers or "_recon" not in scan.response_headers:
        return None
    return scan.response_headers["_recon"]


def _status_tag(ok: bool, ok_label: str = "[PASS]", fail_label: str = "[MISSING]") -> str:
    """Return a plain-text status tag for PDF Paragraph rendering."""
    return ok_label if ok else fail_label


class NumberedCanvas(canvas.Canvas):
    """Two-pass ReportLab canvas that calculates exact total page count and draws headers/footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[dict] = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Top Header
        self.drawString(36, 762, "VULNWATCH EXECUTIVE SECURITY POSTURE ASSESSMENT")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 754, 576, 754)

        # Running Bottom Footer
        self.line(36, 45, 576, 45)
        self.setFont("Helvetica", 8)
        self.drawString(36, 32, "CONFIDENTIAL & PROPRIETARY — FOR AUTHORIZED AUDIT USE ONLY")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 32, page_str)
        self.restoreState()


def generate_pdf_report(scan: Scan, output_path: str) -> str:
    """Generates a professional multi-page PDF executive assessment report using ReportLab.

    Args:
        scan: Scan database model instance.
        output_path: File output path for generated PDF.

    Returns:
        The output file path string.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom Color Palette
    SEV_COLORS = {
        "CRITICAL": colors.HexColor("#dc2626"),
        "HIGH": colors.HexColor("#ea580c"),
        "MEDIUM": colors.HexColor("#d97706"),
        "LOW": colors.HexColor("#2563eb"),
        "INFO": colors.HexColor("#475569"),
    }

    # Paragraph Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=12,
    )

    section_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )

    label_style = ParagraphStyle(
        "ReportLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=11,
        textColor=colors.HexColor("#475569"),
    )

    code_style = ParagraphStyle(
        "ReportCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0284c7"),
    )

    story = []

    # Title Banner
    story.append(Paragraph("Security Assessment Report", title_style))
    story.append(
        Paragraph(
            f"Target URL: <b>{scan.target_url}</b>",
            body_style,
        )
    )
    story.append(Spacer(1, 10))

    # Metadata Grid Table
    scan_dict = scan.to_dict()
    meta_data = [
        [
            Paragraph("Scan ID", label_style),
            Paragraph(f"#{scan.id}", body_style),
            Paragraph("Execution Date", label_style),
            Paragraph(str(scan_dict["started_at"] or "N/A"), body_style),
        ],
        [
            Paragraph("Audit Status", label_style),
            Paragraph(str(scan_dict["status"] or "COMPLETED"), body_style),
            Paragraph("HTTP Status Code", label_style),
            Paragraph(str(scan.status_code or "N/A"), body_style),
        ],
    ]

    meta_table = Table(meta_data, colWidths=[90, 180, 90, 180])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 15))

    # Executive Severity Summary Table
    story.append(Paragraph("Executive Severity Breakdown", section_style))

    summary_headers = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    summary_counts = [
        str(scan.critical_count),
        str(scan.high_count),
        str(scan.medium_count),
        str(scan.low_count),
        str(scan.info_count),
    ]

    sev_summary_data = [
        [
            Paragraph(
                f"<font color='white'><b>{h}</b></font>",
                ParagraphStyle("SH", parent=label_style, alignment=1),
            )
            for h in summary_headers
        ],
        [
            Paragraph(
                f"<b>{c}</b>", ParagraphStyle("SC", parent=body_style, alignment=1)
            )
            for c in summary_counts
        ],
    ]

    sev_table = Table(sev_summary_data, colWidths=[108] * 5)
    sev_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), SEV_COLORS["CRITICAL"]),
                ("BACKGROUND", (1, 0), (1, 0), SEV_COLORS["HIGH"]),
                ("BACKGROUND", (2, 0), (2, 0), SEV_COLORS["MEDIUM"]),
                ("BACKGROUND", (3, 0), (3, 0), SEV_COLORS["LOW"]),
                ("BACKGROUND", (4, 0), (4, 0), SEV_COLORS["INFO"]),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(sev_table)
    story.append(Spacer(1, 15))

    # ── Section 2: Perimeter Reconnaissance & Asset Intelligence ──────────────
    recon = _extract_recon_pdf(scan)
    if recon:
        tls_info = recon.get("tls_info", {})
        redirect_chain = recon.get("redirect_chain", [])
        spf = recon.get("spf_record") or ""
        dmarc = recon.get("dmarc_record") or ""
        dkim = recon.get("dkim_selectors_found", [])
        tech = recon.get("detected_tech", [])
        subdomains = recon.get("ct_subdomains", [])
        ct_count = recon.get("ct_subdomain_count", 0)
        dangling = recon.get("dangling_cnames", [])

        uses_tls = tls_info.get("uses_tls", False)
        http_redirect = bool(tls_info.get("http_to_https_redirect"))
        final_dest = redirect_chain[-1]["url"] if redirect_chain else "—"
        hop_count = max(0, len(redirect_chain) - 1)

        dmarc_enforced = bool(dmarc) and "p=none" not in dmarc.lower()
        dmarc_status = (
            "[ENFORCED]" if dmarc_enforced
            else ("[p=none — NOT ENFORCED]" if dmarc else "[MISSING]")
        )

        # Shared Paragraph styles for recon tables
        recon_label_style = ParagraphStyle(
            "ReconLabel",
            parent=label_style,
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=colors.HexColor("#475569"),
        )
        recon_val_style = ParagraphStyle(
            "ReconVal",
            parent=body_style,
            fontSize=8,
            leading=11,
            wordWrap="CJK",
        )
        recon_ok_style = ParagraphStyle(
            "ReconOk",
            parent=recon_val_style,
            textColor=colors.HexColor("#16a34a"),
            fontName="Helvetica-Bold",
        )
        recon_fail_style = ParagraphStyle(
            "ReconFail",
            parent=recon_val_style,
            textColor=colors.HexColor("#dc2626"),
            fontName="Helvetica-Bold",
        )
        recon_warn_style = ParagraphStyle(
            "ReconWarn",
            parent=recon_val_style,
            textColor=colors.HexColor("#ea580c"),
            fontName="Helvetica-Bold",
        )
        recon_code_style = ParagraphStyle(
            "ReconCode",
            parent=recon_val_style,
            fontName="Courier",
            fontSize=7.5,
            textColor=colors.HexColor("#0369a1"),
            wordWrap="CJK",
        )

        section_header_style = ParagraphStyle(
            "ReconSectionHdr",
            parent=section_style,
            fontSize=11,
            textColor=colors.HexColor("#3730a3"),
            spaceBefore=10,
            spaceAfter=6,
        )

        story.append(Paragraph("Section 2: Perimeter Reconnaissance &amp; Asset Intelligence", section_style))
        story.append(
            Paragraph(
                "Passive, non-intrusive attack surface mapping gathered during scan execution. "
                "Data sources: Certificate Transparency logs (crt.sh), DNS resolver, HTTP response analysis.",
                ParagraphStyle("ReconIntro", parent=body_style, fontSize=8, textColor=colors.HexColor("#64748b")),
            )
        )
        story.append(Spacer(1, 8))

        # ── Table 1: DNS & Transport Hygiene ──────────────────────────────────
        story.append(Paragraph("DNS &amp; Transport Hygiene", section_header_style))

        dns_transport_data = [
            [
                Paragraph("Metric", recon_label_style),
                Paragraph("Value", recon_label_style),
                Paragraph("Status", recon_label_style),
            ],
            [
                Paragraph("HTTPS / TLS Enforcement", recon_label_style),
                Paragraph(str(final_dest)[:80], recon_code_style),
                Paragraph("[ACTIVE]" if uses_tls else "[NOT USED]",
                          recon_ok_style if uses_tls else recon_fail_style),
            ],
            [
                Paragraph("HTTP \u2192 HTTPS Redirect", recon_label_style),
                Paragraph(f"{hop_count} redirect hop(s)", recon_val_style),
                Paragraph("[ACTIVE]" if http_redirect else "[NOT CONFIGURED]",
                          recon_ok_style if http_redirect else recon_fail_style),
            ],
            [
                Paragraph("SPF Record", recon_label_style),
                Paragraph((spf[:80] + "\u2026" if len(spf) > 80 else spf) or "—", recon_code_style),
                Paragraph("[PASS]" if spf else "[MISSING]",
                          recon_ok_style if spf else recon_fail_style),
            ],
            [
                Paragraph("DMARC Record", recon_label_style),
                Paragraph((dmarc[:80] + "\u2026" if len(dmarc) > 80 else dmarc) or "—", recon_code_style),
                Paragraph(dmarc_status,
                          recon_ok_style if dmarc_enforced else (recon_warn_style if dmarc else recon_fail_style)),
            ],
            [
                Paragraph("DKIM Selectors Detected", recon_label_style),
                Paragraph(", ".join(dkim) if dkim else "None found", recon_code_style),
                Paragraph("[PASS]" if dkim else "[NONE DETECTED]",
                          recon_ok_style if dkim else recon_warn_style),
            ],
        ]

        # Add detected technology rows
        if tech:
            for t in tech[:8]:  # cap at 8 to avoid overflow
                dns_transport_data.append([
                    Paragraph(f"Tech: {t.get('label', '')[:30]}", recon_label_style),
                    Paragraph(str(t.get('tech', ''))[:80], recon_code_style),
                    Paragraph("[DETECTED]", recon_warn_style),
                ])

        dns_table = Table(dns_transport_data, colWidths=[150, 240, 150])
        dns_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, 0), 7),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 7),
        ]))
        story.append(dns_table)
        story.append(Spacer(1, 12))

        # ── Table 2: Subdomain Inventory & CNAME Exposure ─────────────────────
        story.append(Paragraph("Discovered Subdomains &amp; CNAME Exposure", section_header_style))

        sub_intro_text = (
            f"Certificate Transparency logs reveal <b>{ct_count}</b> publicly logged subdomain(s) "
            f"for this target. Displaying first {min(ct_count, 20)}."
            if ct_count > 0
            else "No Certificate Transparency subdomains were discovered for this target."
        )
        story.append(Paragraph(sub_intro_text, ParagraphStyle("SubIntro", parent=body_style, fontSize=8)))
        story.append(Spacer(1, 5))

        # Subdomain list as a wrapped table (3-column grid)
        if subdomains:
            # Build rows of 3 subdomain chips per row
            sub_display = subdomains[:30]
            padded = sub_display + [""] * (3 - len(sub_display) % 3) if len(sub_display) % 3 else sub_display
            sub_rows = []
            for i in range(0, len(padded), 3):
                sub_rows.append([
                    Paragraph(padded[i] if padded[i] else "", recon_code_style),
                    Paragraph(padded[i+1] if i+1 < len(padded) and padded[i+1] else "", recon_code_style),
                    Paragraph(padded[i+2] if i+2 < len(padded) and padded[i+2] else "", recon_code_style),
                ])
            sub_table = Table(sub_rows, colWidths=[178, 178, 178])
            sub_table.setStyle(TableStyle([
                ("ROWBACKGROUNDS", (0, 0), (-1, -1),
                 [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(sub_table)
            story.append(Spacer(1, 8))

        # Dangling CNAME warning table
        if dangling:
            story.append(Spacer(1, 4))
            story.append(
                Paragraph(
                    f"\u26a0  Potential Dangling CNAME Records Detected ({len(dangling)})",
                    ParagraphStyle(
                        "DanglingHdr",
                        parent=section_style,
                        fontSize=10,
                        textColor=colors.HexColor("#dc2626"),
                        spaceBefore=6,
                        spaceAfter=4,
                    ),
                )
            )

            cname_data = [
                [
                    Paragraph("Subdomain", recon_label_style),
                    Paragraph("CNAME Target", recon_label_style),
                    Paragraph("Risk Assessment", recon_label_style),
                ],
            ]
            for d in dangling:
                status = d.get("status", "Unknown")
                risk_tier = (
                    "HIGH — Does Not Resolve" if "Does Not" in status
                    else "MEDIUM — Verify Ownership"
                )
                risk_style = recon_fail_style if "Does Not" in status else recon_warn_style
                cname_data.append([
                    Paragraph(d.get("subdomain", "")[:60], recon_code_style),
                    Paragraph(d.get("cname_target", "")[:60], recon_code_style),
                    Paragraph(risk_tier, risk_style),
                ])

            cname_table = Table(cname_data, colWidths=[178, 178, 178])
            cname_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7f1d1d")),
                ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",   (0, 0), (-1, 0), 8),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#fff1f2")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#fecaca")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(cname_table)

        story.append(Spacer(1, 18))
        story.append(
            HRFlowable(
                width="100%",
                thickness=1,
                color=colors.HexColor("#e2e8f0"),
                spaceBefore=4,
                spaceAfter=10,
            )
        )

    # Detailed Findings Section
    story.append(
        Paragraph(f"Detailed Audit Findings ({len(scan.findings)})", section_style)
    )

    if not scan.findings:
        story.append(
            Paragraph(
                "No security findings or observations were recorded during this scan.",
                body_style,
            )
        )
    else:
        for idx, finding in enumerate(scan.findings, 1):
            finding_elements = []

            sev_name = (
                finding.severity.value
                if hasattr(finding.severity, "value")
                else str(finding.severity)
            )
            sev_color = SEV_COLORS.get(sev_name, colors.gray)

            # Header Table for Finding Title + Severity Badge
            title_p = Paragraph(
                f"<b>{idx}. {finding.title}</b>",
                ParagraphStyle(
                    "FTitle",
                    parent=styles["Normal"],
                    fontName="Helvetica-Bold",
                    fontSize=10,
                    leading=13,
                    textColor=colors.HexColor("#0f172a"),
                ),
            )
            badge_p = Paragraph(
                f"<font color='white'><b>{sev_name}</b></font>",
                ParagraphStyle(
                    "FBadge",
                    parent=styles["Normal"],
                    fontName="Helvetica-Bold",
                    fontSize=9,
                    leading=11,
                    alignment=1,
                ),
            )

            card_header = Table([[title_p, badge_p]], colWidths=[430, 110])
            card_header.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#f8fafc")),
                        ("BACKGROUND", (1, 0), (1, 0), sev_color),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("PADDING", (0, 0), (-1, -1), 6),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ]
                )
            )
            finding_elements.append(card_header)

            # Details table (Category & Affected URL)
            details_data = [
                [
                    Paragraph("Category", label_style),
                    Paragraph(finding.category, body_style),
                    Paragraph("Affected URL", label_style),
                    Paragraph(finding.affected_url, code_style),
                ]
            ]
            details_table = Table(details_data, colWidths=[70, 180, 80, 210])
            details_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                        ("PADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )
            finding_elements.append(details_table)

            # Description
            finding_elements.append(Spacer(1, 4))
            finding_elements.append(Paragraph("<b>Description:</b>", label_style))
            finding_elements.append(Paragraph(finding.description, body_style))

            # Evidence (if present)
            if finding.evidence:
                finding_elements.append(Spacer(1, 4))
                finding_elements.append(Paragraph("<b>Evidence:</b>", label_style))
                evidence_text = json.dumps(finding.evidence, indent=2)
                finding_elements.append(Paragraph(evidence_text, code_style))

            # Remediation
            finding_elements.append(Spacer(1, 4))
            finding_elements.append(
                Paragraph("<b>Remediation Action:</b>", label_style)
            )
            finding_elements.append(Paragraph(finding.remediation, body_style))
            finding_elements.append(Spacer(1, 10))
            finding_elements.append(
                HRFlowable(
                    width="100%",
                    thickness=0.5,
                    color=colors.HexColor("#cbd5e1"),
                    spaceBefore=5,
                    spaceAfter=10,
                )
            )

            story.append(KeepTogether(finding_elements))

    # Build PDF document using NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    return output_path
