"""
Report service — exports a completed scan as PDF, JSON, or a standalone HTML
report. Each method returns raw bytes; the API layer wraps them in a
StreamingResponse with the right content-type and filename.
"""
import io
import json
from datetime import datetime, timezone

from app.models.scan import Scan


class ReportService:
    @staticmethod
    def to_json(scan: Scan) -> bytes:
        payload = {
            "scan_id": scan.id,
            "name": scan.name,
            "status": scan.status.value,
            "verdict": scan.verdict.value,
            "scan_type": scan.scan_type.value,
            "security_score": scan.security_score,
            "risk_score": scan.risk_score,
            "total_files": scan.total_files,
            "total_lines": scan.total_lines,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "engine_results": [
                {
                    "engine": r.engine_name, "verdict": r.verdict.value, "confidence": r.confidence,
                    "findings_count": r.findings_count, "duration_ms": r.duration_ms, "summary": r.summary,
                }
                for r in scan.engine_results
            ],
            "vulnerabilities": [
                {
                    "id": v.id, "source_engine": v.source_engine, "title": v.title, "description": v.description,
                    "severity": v.severity.value, "risk_score": v.risk_score, "cwe_id": v.cwe_id, "cve_id": v.cve_id,
                    "owasp_category": v.owasp_category, "file_path": v.file_path,
                    "line_start": v.line_start, "line_end": v.line_end,
                    "suggested_fix": v.suggested_fix, "secure_code_example": v.secure_code_example,
                    "confidence": v.confidence,
                }
                for v in scan.vulnerabilities
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        return json.dumps(payload, indent=2).encode("utf-8")

    @staticmethod
    def to_html(scan: Scan) -> bytes:
        verdict_color = "#00d4b8" if scan.verdict.value == "secure" else "#ff5470"

        rows = "".join(
            f"""<tr>
                <td>{v.severity.value.upper()}</td>
                <td>{v.title}</td>
                <td>{v.cwe_id or '—'}</td>
                <td>{v.file_path}:{v.line_start}</td>
                <td>{v.owasp_category or '—'}</td>
                <td>{v.source_engine}</td>
            </tr>"""
            for v in scan.vulnerabilities
        )

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Scan Report — {scan.name}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, sans-serif; background:#0a0e14; color:#e6edf3; padding:40px; }}
  h1 {{ color:#00d4b8; }}
  .verdict {{ display:inline-block; padding:8px 20px; border-radius:999px; font-weight:700;
              background:{verdict_color}22; color:{verdict_color}; border:1px solid {verdict_color}; }}
  table {{ width:100%; border-collapse:collapse; margin-top:24px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #1e2733; font-size:14px; }}
  th {{ color:#aab4c2; text-transform:uppercase; font-size:11px; letter-spacing:0.05em; }}
  .stat {{ display:inline-block; margin-right:32px; }}
  .stat .num {{ font-size:28px; font-weight:700; color:#00d4b8; }}
  .stat .label {{ color:#6b7686; font-size:12px; text-transform:uppercase; }}
</style></head>
<body>
  <h1>{scan.name}</h1>
  <p>Final verdict: <span class="verdict">{scan.verdict.value.upper()}</span></p>
  <div style="margin-top:24px;">
    <div class="stat"><div class="num">{scan.security_score:.0f}</div><div class="label">Security Score</div></div>
    <div class="stat"><div class="num">{len(scan.vulnerabilities)}</div><div class="label">Findings</div></div>
    <div class="stat"><div class="num">{scan.total_files}</div><div class="label">Files Scanned</div></div>
    <div class="stat"><div class="num">{scan.risk_score:.1f}</div><div class="label">Risk Score</div></div>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>CWE</th><th>Location</th><th>OWASP</th><th>Engine</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="6">No vulnerabilities found.</td></tr>'}</tbody>
  </table>
  <p style="color:#6b7686; margin-top:32px; font-size:12px;">
    Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} ·
    Secure Code Vulnerability Detection Platform
  </p>
</body></html>"""
        return html.encode("utf-8")

    @staticmethod
    def to_pdf(scan: Scan) -> bytes:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("TitleCustom", parent=styles["Title"], textColor=colors.HexColor("#0a0e14"))
        verdict_hex = "#00a890" if scan.verdict.value == "secure" else "#e0334f"

        elements = [
            Paragraph(f"Scan Report — {scan.name}", title_style),
            Spacer(1, 6),
            Paragraph(
                f"<b>Final Verdict:</b> <font color='{verdict_hex}'>{scan.verdict.value.upper()}</font>",
                styles["Normal"],
            ),
            Paragraph(
                f"Security Score: {scan.security_score:.0f}/100 &nbsp;|&nbsp; Risk Score: {scan.risk_score:.1f}/10 "
                f"&nbsp;|&nbsp; Files Scanned: {scan.total_files} &nbsp;|&nbsp; Findings: {len(scan.vulnerabilities)}",
                styles["Normal"],
            ),
            Spacer(1, 16),
            Paragraph("Engine Results", styles["Heading2"]),
        ]

        engine_table_data = [["Engine", "Verdict", "Confidence", "Findings", "Summary"]]
        for r in scan.engine_results:
            engine_table_data.append([
                r.engine_name.upper(), r.verdict.value.upper(), f"{r.confidence:.0%}",
                str(r.findings_count), Paragraph(r.summary, styles["Normal"]),
            ])
        engine_table = Table(engine_table_data, colWidths=[0.8 * inch, 0.9 * inch, 0.8 * inch, 0.7 * inch, 2.6 * inch])
        engine_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#11161f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements += [engine_table, Spacer(1, 16), Paragraph("Vulnerabilities", styles["Heading2"])]

        vuln_data = [["Severity", "Title", "CWE", "Location", "Suggested Fix"]]
        for v in scan.vulnerabilities:
            vuln_data.append([
                v.severity.value.upper(), Paragraph(v.title, styles["Normal"]), v.cwe_id or "—",
                f"{v.file_path}:{v.line_start}", Paragraph(v.suggested_fix[:200], styles["Normal"]),
            ])
        if len(vuln_data) == 1:
            vuln_data.append(["—", "No vulnerabilities found", "—", "—", "—"])

        vuln_table = Table(vuln_data, colWidths=[0.7 * inch, 1.3 * inch, 0.7 * inch, 1.3 * inch, 2 * inch])
        vuln_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#11161f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(vuln_table)

        doc.build(elements)
        return buffer.getvalue()
