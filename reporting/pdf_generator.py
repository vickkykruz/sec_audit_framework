"""
PDF Report Generation using ReportLab.

Generates 5-page structured report:
1. Executive summary (A-F score)
2-4. Detailed findings table
5. Priority fixes + server fingerprint
"""


from reportlab.lib.pagesizes import A4, inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from sec_audit.results import ScanResult
from typing import List


def generate_pdf(scan_result: ScanResult, output_path: str) -> None:
    """
    Generate a complete PDF security audit report from ScanResult.
    
    Args:
        scan_result: Complete scan results with checks and scoring
        output_path: Path to save PDF (e.g., "security_report.pdf")
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*mm,
        leftMargin=2*mm,
        topMargin=2*mm,
        bottomMargin=2*mm
    )
    
    story = []
    styles = getSampleStyleSheet()
    
    # Title page
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.darkblue
    )
    
    story.append(Paragraph("🏛️ Security Audit Framework Report", title_style))
    story.append(Spacer(1, 20))
    
    target_para = Paragraph(
        f"<b>Target:</b> {scan_result.target}<br/>"
        f"<b>Scan Mode:</b> {scan_result.mode}<br/>"
        f"<b>Generated:</b> {scan_result.summary()['generated_at']}",
        styles['Normal']
    )
    story.append(target_para)
    story.append(PageBreak())
    
    # Executive Summary Page
    story.append(Paragraph("📊 EXECUTIVE SUMMARY", styles['Heading2']))
    
    # Score box
    score_data = [
        ["OVERALL GRADE", f"{scan_result.grade} ({scan_result.score_percentage}%)"],
        ["Total Checks", f"{scan_result.total_checks}"],
        ["Passed", f"{scan_result.summary()['status_breakdown'].get('PASS', 0)}"],
        ["High Risk Issues", f"{scan_result.summary()['high_risk_issues']}"],
    ]
    
    score_table = Table(score_data, colWidths=[100*mm, 70*mm])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    
    story.append(score_table)
    story.append(Spacer(1, 20))
    
    # Risk heatmap (simple)
    risk_status = "🟢 PASS" if scan_result.grade in ["A", "B"] else "🟡 WARNING" if scan_result.grade == "C" else "🔴 HIGH RISK"
    story.append(Paragraph(f"<b>Risk Level:</b> {risk_status}", styles['Normal']))
    story.append(PageBreak())
    
    # Detailed Findings by Layer
    layers = {}
    for check in scan_result.checks:
        layer = check.layer
        if layer not in layers:
            layers[layer] = []
        layers[layer].append(check)
    
    for layer_name, checks in layers.items():
        story.append(Paragraph(f"🔍 {layer_name.upper()} LAYER FINDINGS", styles['Heading2']))
        
        table_data = [["ID", "Check", "Status", "Severity", "Details"]]
        
        for check in checks:
            status_emoji = "✅" if check.status == "PASS" else "❌" if check.status == "FAIL" else "⚠️"
            table_data.append([
                check.id,
                check.name[:40],
                f"{status_emoji} {check.status}",
                check.severity,
                check.details[:60] + "..." if len(check.details) > 60 else check.details
            ])
        
        findings_table = Table(table_data, colWidths=[25*mm, 70*mm, 25*mm, 25*mm, 65*mm])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ]))
        
        story.append(findings_table)
        story.append(Spacer(1, 20))
    
    # Priority Fixes Page
    story.append(Paragraph("⚠️ PRIORITY REMEDIATION", styles['Heading2']))
    
    high_risk = [c for c in scan_result.checks if c.status != "PASS" and c.severity == "HIGH"]
    if high_risk:
        fix_data = [["Priority", "Issue", "Recommended Fix"]]
        for i, check in enumerate(high_risk, 1):
            fix_data.append([f"#{i}", f"{check.id}: {check.name}", check.details[:80]])
        
        fix_table = Table(fix_data, colWidths=[15*mm, 80*mm, 95*mm])
        fix_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.red),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(fix_table)
    else:
        story.append(Paragraph("✅ No high-risk issues detected!", styles['Normal']))
    
    doc.build(story)
    print(f"📄 PDF report generated: {output_path}")