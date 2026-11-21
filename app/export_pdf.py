"""
export_pdf.py — build a PDF of the VAPT report.

Uses reportlab if present. If reportlab is not installed on the offline host,
falls back to returning a self-contained printable HTML document (the browser's
"Print to PDF" then produces the PDF with no extra dependency).
"""
import io
from datetime import date

import engine

RISK_COLORS = {
    "Critical": "#b00020", "High": "#e8590c", "Medium": "#f08c00",
    "Low": "#2f9e44", "Information": "#495057", "": "#868e96",
}


def build_pdf(rows, stats):
    try:
        return _build_with_reportlab(rows, stats)
    except Exception:
        # Fall back to printable HTML wrapped as a file.
        html = _build_html(rows, stats)
        return io.BytesIO(html.encode("utf-8"))


def _build_with_reportlab(rows, stats):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
    )

    bio = io.BytesIO()
    doc = SimpleDocTemplate(
        bio, pagesize=landscape(A4),
        leftMargin=10 * mm, rightMargin=10 * mm, topMargin=12 * mm, bottomMargin=12 * mm,
        title="VAPT Assessment Report",
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=18, spaceAfter=4)
    sub = ParagraphStyle("sub", parent=styles["Normal"], fontSize=9, textColor=colors.grey)
    cell = ParagraphStyle("cell", parent=styles["Normal"], fontSize=6.5, leading=8)
    cellb = ParagraphStyle("cellb", parent=cell, fontName="Helvetica-Bold")

    story = []
    story.append(Paragraph("Quarterly VAPT Assessment Report", h1))
    story.append(Paragraph(f"Generated {date.today().strftime('%B %d, %Y')} &nbsp;·&nbsp; "
                           f"{stats['total']} findings &nbsp;·&nbsp; "
                           f"{stats['critical']} Critical, {stats['high']} High &nbsp;·&nbsp; "
                           f"{stats['breached']} risk-tolerance breaches", sub))
    story.append(Spacer(1, 6 * mm))

    head = ["IP / Host", "Vulnerability", "CVE", "Actual Risk", "Detected",
            "Target Fix", "Status", "Risk Tol.", "Owner"]
    data = [[Paragraph(h, cellb) for h in head]]
    for r in rows:
        data.append([
            Paragraph(_esc(r.get("ip_hostname", "")), cell),
            Paragraph(_esc(r.get("vulnerability", ""))[:140], cell),
            Paragraph(_esc(r.get("cve", "")), cell),
            Paragraph(_esc(r.get("actual_risk_classification", "")), cell),
            Paragraph(_esc(r.get("detection_date_disp", "")), cell),
            Paragraph(_esc(r.get("target_fix_date", "")), cell),
            Paragraph(_esc(r.get("remediation_status", "")), cell),
            Paragraph(_esc(r.get("risk_tolerance_objective", "")), cell),
            Paragraph(_esc(r.get("asset_owner", "")), cell),
        ])
    col_widths = [26 * mm, 70 * mm, 30 * mm, 20 * mm, 22 * mm, 22 * mm, 22 * mm, 20 * mm, 22 * mm]
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E78")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
    ]
    # colour the Actual Risk cell per row
    for i, r in enumerate(rows, start=1):
        c = RISK_COLORS.get(r.get("actual_risk_classification", ""), "#868e96")
        style.append(("TEXTCOLOR", (3, i), (3, i), colors.HexColor(c)))
        style.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))
        if r.get("risk_tolerance_objective") == "Breached":
            style.append(("TEXTCOLOR", (7, i), (7, i), colors.HexColor("#b00020")))
            style.append(("FONTNAME", (7, i), (7, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style))
    story.append(t)
    doc.build(story)
    bio.seek(0)
    return bio


def _esc(s):
    return (str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _build_html(rows, stats):
    trs = []
    for r in rows:
        color = RISK_COLORS.get(r.get("actual_risk_classification", ""), "#868e96")
        breach = "color:#b00020;font-weight:bold" if r.get("risk_tolerance_objective") == "Breached" else ""
        trs.append(f"""<tr>
            <td>{_esc(r.get('ip_hostname',''))}</td>
            <td>{_esc(r.get('vulnerability',''))}</td>
            <td>{_esc(r.get('cve',''))}</td>
            <td style="color:{color};font-weight:bold">{_esc(r.get('actual_risk_classification',''))}</td>
            <td>{_esc(r.get('detection_date_disp',''))}</td>
            <td>{_esc(r.get('target_fix_date',''))}</td>
            <td>{_esc(r.get('remediation_status',''))}</td>
            <td style="{breach}">{_esc(r.get('risk_tolerance_objective',''))}</td>
            <td>{_esc(r.get('asset_owner',''))}</td></tr>""")
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>VAPT Assessment Report</title>
<style>
 body{{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#1a1a1a}}
 h1{{color:#1F4E78;margin-bottom:2px}}
 .sub{{color:#666;font-size:13px;margin-bottom:18px}}
 table{{border-collapse:collapse;width:100%;font-size:11px}}
 th{{background:#1F4E78;color:#fff;padding:6px;text-align:left}}
 td{{border:1px solid #ccc;padding:5px;vertical-align:top}}
 tr:nth-child(even) td{{background:#f5f7fa}}
 @media print{{body{{margin:8mm}}}}
</style></head><body>
<h1>Quarterly VAPT Assessment Report</h1>
<div class="sub">Generated {date.today().strftime('%B %d, %Y')} ·
 {stats['total']} findings · {stats['critical']} Critical, {stats['high']} High ·
 {stats['breached']} risk-tolerance breaches &nbsp;—&nbsp; <em>Use your browser's Print → Save as PDF.</em></div>
<table><thead><tr>
 <th>IP / Host</th><th>Vulnerability</th><th>CVE</th><th>Actual Risk</th>
 <th>Detected</th><th>Target Fix</th><th>Status</th><th>Risk Tolerance</th><th>Owner</th>
</tr></thead><tbody>{''.join(trs)}</tbody></table>
</body></html>"""
