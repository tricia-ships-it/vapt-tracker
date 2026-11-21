"""
export_excel.py — build the .xlsx report from the app's findings, matching the
exact column structure and automation of the standalone template. Writes real
formulas (INDEX/MATCH), so the delivered workbook stays live and auditable.
Returns a BytesIO ready for send_file.
"""
import io
from datetime import datetime
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.utils import get_column_letter

import engine

HEADERS = [
    "IP / Hostname", "Device", "Asset Classification", "Vulnerability", "Synopsis",
    "Definition", "CVE (If Applicable)", "Risk Statement", "Reported Risk Rating",
    "Exploit Available", "Actual Risk Classification", "Exploit Reference", "Solution",
    "Asset Owner", "Detection Date", "Target Fix Date", "Time to Fix (Days)",
    "Remediation Status", "Actual Fix Date", "Risk Tolerance Objective",
    "Exception Requested?", "Exception Approved By", "Revised Target Fix Date",
    "Asset Owner's Comment", "Comment",
]
# source dict key per column letter (None = formula)
KEYMAP = {
    "A": "ip_hostname", "B": "device", "C": "asset_classification", "D": "vulnerability",
    "E": "synopsis", "F": "definition", "G": "cve", "H": "risk_statement",
    "I": "reported_risk", "J": "exploit_available", "K": None, "L": "exploit_reference",
    "M": "solution", "N": "asset_owner", "O": "detection_date", "P": None, "Q": None,
    "R": "remediation_status", "S": "actual_fix_date", "T": None, "U": "exception_requested",
    "V": "exception_approved_by", "W": "revised_target_fix_date", "X": "asset_owners_comment",
    "Y": "comment",
}
AUTO_COLS = {"K", "P", "Q", "T"}
DATE_KEYS = {"detection_date", "actual_fix_date", "revised_target_fix_date"}


def _parse_iso(s):
    if not s:
        return None
    try:
        return datetime.strptime(str(s)[:10], "%Y-%m-%d")
    except ValueError:
        return None


def build_excel(rows):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Findings"

    HEADER_FILL = PatternFill("solid", fgColor="1F4E78")
    HEADER_FONT = Font(name="Arial", bold=True, color="FFFFFF", size=10)
    AUTO_FILL = PatternFill("solid", fgColor="E2EFDA")
    thin = Side(style="thin", color="BFBFBF")
    BORDER = Border(left=thin, right=thin, top=thin, bottom=thin)
    WRAP = Alignment(vertical="top", wrap_text=True)
    CENTER = Alignment(vertical="top", horizontal="center", wrap_text=True)

    for idx, h in enumerate(HEADERS, 1):
        c = ws.cell(row=1, column=idx, value=h)
        c.fill, c.font, c.alignment, c.border = HEADER_FILL, HEADER_FONT, CENTER, BORDER
    ws.row_dimensions[1].height = 42
    ws.freeze_panes = "A2"

    widths = {"A": 18, "B": 20, "C": 16, "D": 30, "E": 40, "F": 45, "G": 20, "H": 40,
              "I": 14, "J": 14, "K": 16, "L": 35, "M": 40, "N": 16, "O": 14, "P": 14,
              "Q": 12, "R": 18, "S": 14, "T": 18, "U": 14, "V": 18, "W": 18, "X": 30, "Y": 30}
    for col, w in widths.items():
        ws.column_dimensions[col].width = w

    # --- lookup sheets (RiskMatrix, FixWindow, Lists, AssetOwners) ---
    _build_lookup_sheets(wb)
    n_matrix = len(engine._MATRIX_ROWS)

    # --- data rows ---
    for i, row in enumerate(rows, start=2):
        for col, key in KEYMAP.items():
            cell = ws[f"{col}{i}"]
            cell.border = BORDER
            cell.alignment = WRAP
            cell.font = Font(name="Arial", size=10)
            if col in AUTO_COLS:
                cell.fill = AUTO_FILL
            if key is None:
                continue
            val = row.get(key, "")
            if key in DATE_KEYS:
                dv = _parse_iso(val)
                if dv:
                    cell.value = dv
                    cell.number_format = "mmm dd, yyyy"
            else:
                cell.value = val

        # formulas
        ws[f"K{i}"] = (
            f'=IF(OR($C{i}="",$I{i}="",$J{i}=""),"",'
            f'IFERROR(INDEX(RiskMatrix!$B$2:$B${n_matrix+1},'
            f'MATCH($C{i}&"|"&$I{i}&"|"&$J{i},RiskMatrix!$A$2:$A${n_matrix+1},0)),""))'
        )
        ws[f"P{i}"] = (
            f'=IF(OR($O{i}="",$K{i}=""),"",'
            f'IFERROR(IF(INDEX(FixWindow!$B$2:$B$6,MATCH($K{i},FixWindow!$A$2:$A$6,0))="","",'
            f'$O{i}+INDEX(FixWindow!$B$2:$B$6,MATCH($K{i},FixWindow!$A$2:$A$6,0))),""))'
        )
        ws[f"P{i}"].number_format = "mmm dd, yyyy"
        ws[f"Q{i}"] = f'=IF(OR($P{i}="",$O{i}=""),"",$P{i}-$O{i})'
        ws[f"T{i}"] = (
            f'=IF(OR($R{i}="Not Applicable",$R{i}="Risk Accepted",$R{i}="Exception Approved"),"Not Applicable",'
            f'IF($S{i}="","",'
            f'IF(IF($W{i}<>"",$W{i},$P{i})="","Met",'
            f'IF($S{i}<=IF($W{i}<>"",$W{i},$P{i}),"Met","Breached"))))'
        )

    maxrow = max(len(rows) + 1, 2)
    _add_validations(ws, maxrow)
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    return bio


def _build_lookup_sheets(wb):
    HEADER_FILL = PatternFill("solid", fgColor="1F4E78")
    HF = Font(name="Arial", bold=True, color="FFFFFF")

    lk = wb.create_sheet("RiskMatrix")
    lk["A1"], lk["B1"] = "Key", "Actual Risk Classification"
    for c in ("A1", "B1"):
        lk[c].font, lk[c].fill = HF, HEADER_FILL
    for i, (a, r, e, actual) in enumerate(engine._MATRIX_ROWS, start=2):
        lk.cell(row=i, column=1, value=f"{a}|{r}|{e}")
        lk.cell(row=i, column=2, value=actual)
    lk.column_dimensions["A"].width = 34
    lk.column_dimensions["B"].width = 26

    sla = wb.create_sheet("FixWindow")
    sla["A1"], sla["B1"] = "Actual Risk Classification", "Fix Window (Days)"
    for c in ("A1", "B1"):
        sla[c].font, sla[c].fill = HF, HEADER_FILL
    for i, sev in enumerate(["Critical", "High", "Medium", "Low", "Information"], start=2):
        sla.cell(row=i, column=1, value=sev)
        days = engine.SLA_DAYS.get(sev)
        sla.cell(row=i, column=2, value=days if days is not None else "")
    sla.column_dimensions["A"].width = 26

    lists = wb.create_sheet("Lists")
    lists["A1"], lists["B1"], lists["C1"], lists["D1"] = "Risk", "Exploit", "Status", "YesNo"
    for c in ("A1", "B1", "C1", "D1"):
        lists[c].font, lists[c].fill = HF, HEADER_FILL
    for i, v in enumerate(engine.SEVERITIES, start=2):
        lists.cell(row=i, column=1, value=v)
    for i, v in enumerate(engine.EXPLOIT_OPTIONS, start=2):
        lists.cell(row=i, column=2, value=v)
    for i, v in enumerate(engine.REMEDIATION_STATUSES, start=2):
        lists.cell(row=i, column=3, value=v)
    for i, v in enumerate(["Yes", "No"], start=2):
        lists.cell(row=i, column=4, value=v)


def _add_validations(ws, maxrow):
    defs = [
        ("=Lists!$A$2:$A$6", "C"), ("=Lists!$A$2:$A$6", "I"),
        ("=Lists!$B$2:$B$4", "J"), ("=Lists!$C$2:$C$10", "R"),
        ("=Lists!$D$2:$D$3", "U"),
    ]
    for formula, col in defs:
        dv = DataValidation(type="list", formula1=formula, allow_blank=True)
        dv.add(f"{col}2:{col}{maxrow}")
        ws.add_data_validation(dv)
