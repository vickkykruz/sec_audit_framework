"""
Result aggregation, scoring, and executive summary generation.

Calculates:
- Overall A-F grade (90%+ = A, 80%+ = B, etc.)
- Risk distribution (critical/high/medium/low)
- Top 5 priority remediation items
- Plain-language executive summary paragraph
"""


from typing import List
from sec_audit.results import CheckResult, Status, Severity


def generate_priority_fixes(results: List[CheckResult]) -> str:
    """Generate Top 5 Priority Fixes section for PDF."""
    # Filter non-PASS results, sort by severity then status
    issues = [
        r for r in results 
        if r.status != Status.PASS
    ]
    priority = sorted(
        issues,
        key=lambda r: (r.severity.value, 0 if r.status == Status.FAIL else 1)
    )[:5]
    
    if not priority:
        return """
        <div style="padding: 20px; background: #e8f5e8; border-left: 5px solid #28a745;">
            <h3>🎉 No Priority Fixes Needed</h3>
            <p>All critical security checks passed. Excellent baseline!</p>
        </div>
        """
    
    fixes_html = """
    <div style="padding: 20px; background: #fff3cd; border-left: 5px solid #ffc107;">
        <h3>🔥 Top 5 Priority Fixes</h3>
        <ol style="margin-top: 10px;">
    """
    for i, result in enumerate(priority, 1):
        icon = "❌" if result.status == Status.FAIL else "⚠️"
        fixes_html += f"""
            <li style="margin-bottom: 12px;">
                <b>{icon} {result.name}</b> 
                <span style="color: #dc3545; font-weight: bold;">[{result.severity.name}]</span><br/>
                <i>{result.details}</i>
            </li>
        """
    fixes_html += "</ol></div>"
    return fixes_html


def generate_fingerprint(versions: dict) -> str:
    """Generate server fingerprint section."""
    fingerprint_html = """
    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px;">
        <h3>🖥️ Server Fingerprint</h3>
        <table style="width: 100%; border-collapse: collapse;">
    """
    
    # Ordered display
    display_versions = {
        "os": "OS",
        "docker": "Docker Engine", 
        "webserver": "Web Server",
        "app": "Application",
        "python": "Python Runtime"
    }
    
    for key, label in display_versions.items():
        version = versions.get(key, "N/A")
        bg_color = "#d4edda" if version != "N/A" else "#f8d7da"
        fingerprint_html += f"""
            <tr>
                <td style="padding: 8px; font-weight: bold; width: 40%;">{label}:</td>
                <td style="padding: 8px; background: {bg_color}; border-radius: 4px;">
                    <code>{version}</code>
                </td>
            </tr>
        """
    
    fingerprint_html += "</table></div>"
    return fingerprint_html