"""
PDF Report Generation using ReportLab.

Generates a structured security audit report with professional design:
- Consistent color palette
- Running page headers/footers
- Color-coded grade, status cells, and risk levels
- Proper margins and typography
- Visual title page with banner
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph,
    Spacer, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate
from sec_audit.results import ScanResult
from sec_audit.baseline import HARDENED_FLASK_BASELINE
from typing import List
import datetime

# ── Brand palette ────────────────────────────────────────────────────────────
NAVY        = colors.HexColor("#0D1B2A")
STEEL       = colors.HexColor("#1B3A5C")
ACCENT      = colors.HexColor("#2196F3")
PASS_GREEN  = colors.HexColor("#2E7D32")
FAIL_RED    = colors.HexColor("#C62828")
WARN_AMBER  = colors.HexColor("#F57F17")
LIGHT_GREEN = colors.HexColor("#E8F5E9")
LIGHT_RED   = colors.HexColor("#FFEBEE")
LIGHT_AMBER = colors.HexColor("#FFFDE7")
ROW_ALT     = colors.HexColor("#F5F7FA")
RULE_GREY   = colors.HexColor("#CFD8DC")
TEXT_DARK   = colors.HexColor("#212121")
TEXT_MUTED  = colors.HexColor("#546E7A")

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm


# ── Grade colour helper ───────────────────────────────────────────────────────
def _grade_color(grade: str):
    return {
        "A": PASS_GREEN,
        "B": colors.HexColor("#558B2F"),
        "C": WARN_AMBER,
        "D": colors.HexColor("#E65100"),
        "F": FAIL_RED,
    }.get(grade.upper(), STEEL)


def _status_bg(status: str):
    return {
        "PASS": LIGHT_GREEN,
        "FAIL": LIGHT_RED,
        "WARN": LIGHT_AMBER,
    }.get(status.upper(), colors.white)


def _status_fg(status: str):
    return {
        "PASS": PASS_GREEN,
        "FAIL": FAIL_RED,
        "WARN": WARN_AMBER,
    }.get(status.upper(), TEXT_DARK)


def _risk_bg(risk: str):
    risk_upper = risk.upper() if risk else ""
    if "HIGH" in risk_upper or "CRIT" in risk_upper:
        return LIGHT_RED
    if "MED" in risk_upper:
        return LIGHT_AMBER
    return LIGHT_GREEN


# ── Page header/footer via canvas callbacks ───────────────────────────────────
def _make_page_callbacks(title: str, target: str, total_pages_ref: list):
    """Return onFirstPage and onLaterPages callbacks."""

    def _header_footer(canv, doc):
        canv.saveState()
        page_num = doc.page

        # Header bar
        canv.setFillColor(NAVY)
        canv.rect(MARGIN, PAGE_H - 14*mm, PAGE_W - 2*MARGIN, 10*mm, fill=1, stroke=0)
        canv.setFillColor(colors.white)
        canv.setFont("Helvetica-Bold", 8)
        canv.drawString(MARGIN + 3*mm, PAGE_H - 9*mm, title)
        canv.setFont("Helvetica", 8)
        canv.drawRightString(PAGE_W - MARGIN - 3*mm, PAGE_H - 9*mm, f"Target: {target}")

        # Footer rule + text
        canv.setStrokeColor(RULE_GREY)
        canv.setLineWidth(0.5)
        canv.line(MARGIN, 12*mm, PAGE_W - MARGIN, 12*mm)
        canv.setFillColor(TEXT_MUTED)
        canv.setFont("Helvetica", 7)
        canv.drawString(MARGIN, 8*mm, f"Generated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')}  •  CONFIDENTIAL")
        canv.drawRightString(PAGE_W - MARGIN, 8*mm, f"Page {page_num}")

        canv.restoreState()

    def _first_page(canv, doc):
        _header_footer(canv, doc)

    def _later_pages(canv, doc):
        _header_footer(canv, doc)

    return _first_page, _later_pages


# ── Style helpers ─────────────────────────────────────────────────────────────
def _build_styles():
    base = getSampleStyleSheet()
    styles = {}

    styles["h1"] = ParagraphStyle(
        "h1", parent=base["Normal"],
        fontName="Helvetica-Bold", fontSize=22,
        textColor=colors.white, alignment=TA_CENTER,
        spaceAfter=4,
    )
    styles["h2"] = ParagraphStyle(
        "h2", parent=base["Normal"],
        fontName="Helvetica-Bold", fontSize=13,
        textColor=NAVY, spaceBefore=14, spaceAfter=6,
        borderPad=0,
    )
    styles["h3"] = ParagraphStyle(
        "h3", parent=base["Normal"],
        fontName="Helvetica-Bold", fontSize=10,
        textColor=STEEL, spaceBefore=8, spaceAfter=4,
    )
    styles["body"] = ParagraphStyle(
        "body", parent=base["Normal"],
        fontName="Helvetica", fontSize=9,
        textColor=TEXT_DARK, leading=14,
    )
    styles["muted"] = ParagraphStyle(
        "muted", parent=base["Normal"],
        fontName="Helvetica", fontSize=8,
        textColor=TEXT_MUTED, leading=12,
    )
    styles["meta"] = ParagraphStyle(
        "meta", parent=base["Normal"],
        fontName="Helvetica", fontSize=9,
        textColor=colors.white, alignment=TA_CENTER,
        leading=16,
    )
    return styles


# ── Section heading with accent rule ─────────────────────────────────────────
def _section(title: str, styles) -> list:
    return [
        Paragraph(title, styles["h2"]),
        HRFlowable(width="100%", thickness=1.5, color=ACCENT, spaceAfter=6),
    ]


# ── Grade badge table ─────────────────────────────────────────────────────────
def _grade_badge(scan_result: ScanResult, styles) -> Table:
    grade = scan_result.grade
    gc = _grade_color(grade)
    summary = scan_result.summary()
    passed = summary["status_breakdown"].get("PASS", 0)
    high_risk = summary["high_risk_issues"]

    data = [
        [
            Paragraph(f'<font size="36"><b>{grade}</b></font>', ParagraphStyle(
                "grade_big", fontName="Helvetica-Bold", fontSize=36,
                textColor=colors.white, alignment=TA_CENTER,
            )),
            Table(
                [
                    [Paragraph("<b>Score</b>", ParagraphStyle("kl", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white)),
                     Paragraph(f"{scan_result.score_percentage}%", ParagraphStyle("kv", fontName="Helvetica-Bold", fontSize=18, textColor=colors.white))],
                    [Paragraph("<b>Passed</b>", ParagraphStyle("kl", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white)),
                     Paragraph(f"{passed} / {scan_result.total_checks}", ParagraphStyle("kv", fontName="Helvetica", fontSize=11, textColor=colors.white))],
                    [Paragraph("<b>High Risk</b>", ParagraphStyle("kl", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white)),
                     Paragraph(str(high_risk), ParagraphStyle("kv", fontName="Helvetica-Bold", fontSize=11, textColor=LIGHT_RED if high_risk > 0 else colors.white))],
                ],
                colWidths=[35*mm, 55*mm],
            ),
        ]
    ]

    t = Table(data, colWidths=[40*mm, 100*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), gc),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("ROUNDEDCORNERS", [6, 6, 6, 6]),
    ]))
    return t


# ── Main generate function ────────────────────────────────────────────────────
def generate_pdf(scan_result: ScanResult, output_path: str) -> None:
    """
    Generate a professional PDF security audit report from ScanResult.

    Args:
        scan_result: Complete scan results with checks and scoring
        output_path: Path to save PDF (e.g., "security_report.pdf")
    """
    styles = _build_styles()

    report_title = "Security Audit Report"
    on_first_page, on_later_pages = _make_page_callbacks(
        report_title, scan_result.target, []
    )

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=MARGIN,
        leftMargin=MARGIN,
        topMargin=22 * mm,   # room for header bar
        bottomMargin=18 * mm,  # room for footer
        title=report_title,
        author="Security Audit Framework",
    )

    story = []

    # ── TITLE BANNER ──────────────────────────────────────────────────────────
    # Dark navy banner table acting as a cover block
    banner_data = [[
        Paragraph("Security Audit Framework", ParagraphStyle(
            "banner_sub", fontName="Helvetica", fontSize=11,
            textColor=colors.HexColor("#90CAF9"), alignment=TA_CENTER,
        )),
    ], [
        Paragraph(report_title, styles["h1"]),
    ], [
        Paragraph(
            f"<b>Target:</b> {scan_result.target}<br/>"
            f"<b>Scan Mode:</b> {scan_result.mode}<br/>"
            f"<b>Generated:</b> {scan_result.generated_at}",
            styles["meta"],
        ),
    ]]

    banner = Table(banner_data, colWidths=[PAGE_W - 2*MARGIN])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(banner)
    story.append(Spacer(1, 14))

    # ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
    story.extend(_section("Executive Summary", styles))
    story.append(_grade_badge(scan_result, styles))
    story.append(Spacer(1, 14))

    # ── ATTACK SURFACE HEATMAP ────────────────────────────────────────────────
    story.extend(_section("Attack Surface Heatmap", styles))

    layer_data = scan_result.layer_summary()
    layers_order = ["app", "webserver", "container", "host"]
    layer_labels = {"app": "Web App", "webserver": "Web Server", "container": "Container", "host": "Host"}

    heatmap_rows = [[
        Paragraph("<b>Layer</b>", ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white, alignment=TA_CENTER)),
        Paragraph("<b>Pass Rate</b>", ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white, alignment=TA_CENTER)),
        Paragraph("<b>Status</b>", ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white, alignment=TA_CENTER)),
        Paragraph("<b>Risk</b>", ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white, alignment=TA_CENTER)),
    ]]

    heatmap_style = [
        ("BACKGROUND", (0, 0), (-1, 0), STEEL),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, RULE_GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
    ]

    for i, layer in enumerate(layers_order, 1):
        if layer in layer_data:
            stats = layer_data[layer]
            risk = stats.get("risk", "")
            bg = _risk_bg(risk)
            heatmap_rows.append([
                layer_labels.get(layer, layer),
                f"{stats['pass_rate']}%  ({stats['passed']}/{stats['total']})",
                stats.get("color", ""),
                risk,
            ])
            heatmap_style.append(("BACKGROUND", (0, i), (-1, i), bg))

    heatmap_table = Table(heatmap_rows, colWidths=[40*mm, 55*mm, 30*mm, 45*mm])
    heatmap_table.setStyle(TableStyle(heatmap_style))
    story.append(heatmap_table)
    story.append(Spacer(1, 14))

    # ── CONFIGURATION DRIFT ───────────────────────────────────────────────────
    story.extend(_section("Configuration Drift vs Hardened Flask LMS", styles))
    drift = scan_result.compare_to_baseline(HARDENED_FLASK_BASELINE)

    improved = ", ".join(drift["improved_checks"]) or "None"
    regressed = ", ".join(drift["regressed_checks"]) or "None"

    _dk = ParagraphStyle("drift_key", fontName="Helvetica-Bold", fontSize=9, textColor=TEXT_DARK, leading=13, wordWrap="CJK")
    _dv = ParagraphStyle("drift_val", fontName="Helvetica", fontSize=9, textColor=TEXT_DARK, leading=13, wordWrap="CJK")

    drift_data = [
        [Paragraph("Grade Delta", _dk),    Paragraph(str(drift["grade_delta"]), _dv)],
        [Paragraph("Pass Delta", _dk),     Paragraph(f"{drift['pass_delta']} checks vs baseline", _dv)],
        [Paragraph("Improved Checks", _dk), Paragraph(improved, _dv)],
        [Paragraph("Regressed Checks", _dk), Paragraph(regressed, _dv)],
    ]

    drift_table = Table(drift_data, colWidths=[50*mm, PAGE_W - 2*MARGIN - 50*mm])
    drift_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, RULE_GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, ROW_ALT]),
    ]))
    story.append(drift_table)
    story.append(Spacer(1, 14))

    # ── DETAILED FINDINGS BY LAYER ────────────────────────────────────────────
    layers: dict = {}
    for check in scan_result.checks:
        layers.setdefault(check.layer, []).append(check)

    for layer_name, checks in layers.items():
        story.extend(_section(f"{layer_name.upper()} Layer Findings", styles))

        col_hdr_style = ParagraphStyle("colhdr", fontName="Helvetica-Bold", fontSize=8, textColor=colors.white, alignment=TA_CENTER)
        table_data = [[
            Paragraph("ID", col_hdr_style),
            Paragraph("Check", col_hdr_style),
            Paragraph("Status", col_hdr_style),
            Paragraph("Severity", col_hdr_style),
            Paragraph("Details", col_hdr_style),
        ]]

        row_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), STEEL),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, RULE_GREY),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
        ]

        cell_style = ParagraphStyle("cell", fontName="Helvetica", fontSize=8, textColor=TEXT_DARK, leading=11, wordWrap="CJK")
        cell_center = ParagraphStyle("cell_c", fontName="Helvetica", fontSize=8, textColor=TEXT_DARK, leading=11, alignment=TA_CENTER, wordWrap="CJK")

        for row_idx, check in enumerate(checks, 1):
            status = check.status.upper()
            status_label = {"PASS": "PASS", "FAIL": "FAIL", "WARN": "WARN"}.get(status, status)
            status_fg = _status_fg(status)
            status_bg = _status_bg(status)

            table_data.append([
                Paragraph(check.id, cell_style),
                Paragraph(check.name, cell_style),
                Paragraph(
                    f'<font color="{status_fg.hexval()}"><b>{status_label}</b></font>',
                    ParagraphStyle("status_cell", fontSize=8, alignment=TA_CENTER, leading=11, wordWrap="CJK"),
                ),
                Paragraph(str(check.severity), cell_center),
                Paragraph(check.details, cell_style),
            ])
            row_styles.append(("BACKGROUND", (2, row_idx), (2, row_idx), status_bg))
            if row_idx % 2 == 0:
                row_styles.append(("BACKGROUND", (0, row_idx), (1, row_idx), ROW_ALT))
                row_styles.append(("BACKGROUND", (3, row_idx), (4, row_idx), ROW_ALT))

        findings_table = Table(
            table_data,
            colWidths=[22*mm, 65*mm, 22*mm, 22*mm, PAGE_W - 2*MARGIN - 131*mm],
            repeatRows=1,
        )
        findings_table.setStyle(TableStyle(row_styles))
        story.append(KeepTogether(findings_table))
        story.append(Spacer(1, 16))

    # ── CRITICAL ATTACK PATHS ─────────────────────────────────────────────────
    story.extend(_section("Critical Attack Paths", styles))
    paths = scan_result.attack_paths()

    if paths:
        col_hdr_style = ParagraphStyle("colhdr2", fontName="Helvetica-Bold", fontSize=8, textColor=colors.white, alignment=TA_CENTER)
        path_data = [[
            Paragraph("#", col_hdr_style),
            Paragraph("Attack Path", col_hdr_style),
            Paragraph("Risk", col_hdr_style),
            Paragraph("Score", col_hdr_style),
        ]]
        path_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), FAIL_RED),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, RULE_GREY),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]

        for i, path in enumerate(paths[:3], 1):
            risk = path.get("risk", "")
            path_data.append([
                str(i),
                path["name"][:55],
                risk,
                f"{path['score']:.1f}",
            ])
            path_styles.append(("BACKGROUND", (0, i), (-1, i), _risk_bg(risk)))

        path_table = Table(path_data, colWidths=[12*mm, 95*mm, 30*mm, 25*mm])
        path_table.setStyle(TableStyle(path_styles))
        story.append(KeepTogether(path_table))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f"<b>{len(paths)}</b> attack path(s) identified. Remediate highest-score paths first.",
            styles["body"],
        ))
    else:
        story.append(Paragraph("No multi-layer attack paths detected.", styles["body"]))

    # ── SERVER FINGERPRINT ────────────────────────────────────────────────────
    story.append(Spacer(1, 14))
    story.extend(_section("Server Fingerprint", styles))

    fp_data = [
        ["Detected Stack", scan_result.stack_fingerprint],
        ["Inference Method", "HTTP headers, framework behaviours, container/host findings"],
    ]
    fp_table = Table(fp_data, colWidths=[50*mm, PAGE_W - 2*MARGIN - 50*mm])
    fp_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, RULE_GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, ROW_ALT]),
        ("TEXTCOLOR", (0, 0), (-1, -1), TEXT_DARK),
    ]))
    story.append(fp_table)

    # ── BUILD ─────────────────────────────────────────────────────────────────
    doc.build(story, onFirstPage=on_first_page, onLaterPages=on_later_pages)
    print(f"PDF report generated: {output_path}")