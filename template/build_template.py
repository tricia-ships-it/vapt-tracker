#!/usr/bin/env python3
"""
Build the VAPT Quarterly Assessment report template (.xlsx) with all automation baked in.
Matches Patricia's report structure, with XLOOKUP logic re-expressed via INDEX/MATCH
(LibreOffice-safe). No external links, no post-2007 spill functions.
"""
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.utils import get_column_letter
from openpyxl.comments import Comment

wb = openpyxl.Workbook()

# ---------------------------------------------------------------------------
# Sheet 1: Findings (the main report)
# ---------------------------------------------------------------------------
ws = wb.active
ws.title = "Findings"

# Column order exactly as specified in the request.
headers = [
    "IP / Hostname",                 # A
    "Device",                        # B
    "Asset Classification",          # C  (Critical/High/Medium/Low/Information)
    "Vulnerability",                 # D
    "Synopsis",                      # E
    "Definition",                    # F
    "CVE (If Applicable)",           # G
    "Risk Statement",                # H
    "Reported Risk Rating",          # I  (Critical/High/Medium/Low/Information)
    "Exploit Available",             # J  (Yes/No/Unknown)
    "Actual Risk Classification",    # K  (AUTO: INDEX/MATCH on C|I|J)
    "Exploit Reference",             # L
    "Solution",                      # M
    "Asset Owner",                   # N  (dropdown from Asset Owners sheet)
    "Detection Date",                # O  (scan/report date)
    "Target Fix Date",               # P  (AUTO: Detection + SLA by K)
    "Time to Fix (Days)",            # Q  (AUTO: P - O)
    "Remediation Status",            # R  (dropdown)
    "Actual Fix Date",               # S  (AUTO on Fixed/Not Applicable, editable)
    "Risk Tolerance Objective",      # T  (AUTO: Met/Breached/Not Applicable)
    "Exception Requested?",          # U  (Yes/No)
    "Exception Approved By",         # V  (appears when exception requested)
    "Revised Target Fix Date",       # W  (appears when exception requested)
    "Asset Owner's Comment",         # X
    "Comment",                       # Y
]

# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------
HEADER_FILL = PatternFill("solid", fgColor="1F4E78")
HEADER_FONT = Font(name="Arial", bold=True, color="FFFFFF", size=10)
AUTO_FILL = PatternFill("solid", fgColor="E2EFDA")   # green-ish = automated, do not edit
INPUT_FILL = PatternFill("solid", fgColor="FFFFFF")  # white = user input
EXAMPLE_FILL = PatternFill("solid", fgColor="FFF2CC")  # yellow = example row
thin = Side(style="thin", color="BFBFBF")
BORDER = Border(left=thin, right=thin, top=thin, bottom=thin)
WRAP = Alignment(vertical="top", wrap_text=True)
CENTER = Alignment(vertical="top", horizontal="center", wrap_text=True)

# Columns that are automated (formula-driven) — shade them green in data rows.
AUTO_COLS = {"K", "P", "Q", "S", "T"}

# Write header row
for idx, h in enumerate(headers, start=1):
    c = ws.cell(row=1, column=idx, value=h)
    c.fill = HEADER_FILL
    c.font = HEADER_FONT
    c.alignment = CENTER
    c.border = BORDER
ws.row_dimensions[1].height = 42
ws.freeze_panes = "A2"

# Column widths
widths = {
    "A": 18, "B": 20, "C": 16, "D": 30, "E": 40, "F": 45, "G": 20, "H": 40,
    "I": 14, "J": 14, "K": 16, "L": 35, "M": 40, "N": 16, "O": 14, "P": 14,
    "Q": 12, "R": 18, "S": 14, "T": 18, "U": 14, "V": 18, "W": 18, "X": 30, "Y": 30,
}
for col, w in widths.items():
    ws.column_dimensions[col].width = w

# ---------------------------------------------------------------------------
# Lookup sheet: the risk matrix (Asset Classification | Reported Risk | Exploit -> Actual)
# This replaces the inline XLOOKUP array with a real lookup table + INDEX/MATCH.
# ---------------------------------------------------------------------------
lk = wb.create_sheet("RiskMatrix")
lk["A1"] = "Key (AssetClass|ReportedRisk|Exploit)"
lk["B1"] = "Actual Risk Classification"
for cell in ("A1", "B1"):
    lk[cell].font = Font(name="Arial", bold=True, color="FFFFFF")
    lk[cell].fill = HEADER_FILL

# Exact mapping transcribed from the user's XLOOKUP (keys -> results), in order.
matrix = [
    ("Critical|Critical|Yes", "Critical"),
    ("Critical|Critical|No", "Critical"),
    ("Critical|Critical|Unknown", "Critical"),
    ("Critical|High|Yes", "Critical"),
    ("Critical|High|No", "Critical"),
    ("Critical|High|Unknown", "Critical"),
    ("Critical|Medium|Yes", "Critical"),
    ("Critical|Medium|No", "High"),
    ("Critical|Medium|Unknown", "High"),
    ("Critical|Low|Yes", "High"),
    ("Critical|Low|No", "Medium"),
    ("Critical|Low|Unknown", "Medium"),
    ("Critical|Information|Yes", "Medium"),
    ("Critical|Information|No", "Low"),
    ("Critical|Information|Unknown", "Low"),
    ("High|Critical|Yes", "Critical"),
    ("High|Critical|No", "Critical"),
    ("High|Critical|Unknown", "Critical"),
    ("High|High|Yes", "Critical"),
    ("High|High|No", "High"),
    ("High|High|Unknown", "High"),
    ("High|Medium|Yes", "Critical"),
    ("High|Medium|No", "High"),
    ("High|Medium|Unknown", "High"),
    ("High|Low|Yes", "High"),
    ("High|Low|No", "Medium"),
    ("High|Low|Unknown", "Medium"),
    ("High|Information|Yes", "Medium"),
    ("High|Information|No", "Low"),
    ("High|Information|Unknown", "Low"),
    ("Medium|Critical|Yes", "Critical"),
    ("Medium|Critical|No", "High"),
    ("Medium|Critical|Unknown", "High"),
    ("Medium|High|Yes", "Critical"),
    ("Medium|High|No", "High"),
    ("Medium|High|Unknown", "High"),
    ("Medium|Medium|Yes", "High"),
    ("Medium|Medium|No", "Medium"),
    ("Medium|Medium|Unknown", "Medium"),
    ("Medium|Low|Yes", "Medium"),
    ("Medium|Low|No", "Low"),
    ("Medium|Low|Unknown", "Low"),
    ("Medium|Information|Yes", "Low"),
    ("Medium|Information|No", "Information"),
    ("Medium|Information|Unknown", "Information"),
    ("Low|Critical|Yes", "High"),
    ("Low|Critical|No", "Medium"),
    ("Low|Critical|Unknown", "Medium"),
    ("Low|High|Yes", "High"),
    ("Low|High|No", "Medium"),
    ("Low|High|Unknown", "Medium"),
    ("Low|Medium|Yes", "Medium"),
    ("Low|Low|No", "Low"),  # placeholder corrected below
]
# NOTE: the user's result array had a known length; transcribe fully and correctly.
matrix = [
    ("Critical|Critical|Yes", "Critical"),
    ("Critical|Critical|No", "Critical"),
    ("Critical|Critical|Unknown", "Critical"),
    ("Critical|High|Yes", "Critical"),
    ("Critical|High|No", "Critical"),
    ("Critical|High|Unknown", "Critical"),
    ("Critical|Medium|Yes", "Critical"),
    ("Critical|Medium|No", "High"),
    ("Critical|Medium|Unknown", "High"),
    ("Critical|Low|Yes", "High"),
    ("Critical|Low|No", "Medium"),
    ("Critical|Low|Unknown", "Medium"),
    ("Critical|Information|Yes", "Medium"),
    ("Critical|Information|No", "Low"),
    ("Critical|Information|Unknown", "Low"),
    ("High|Critical|Yes", "Critical"),
    ("High|Critical|No", "Critical"),
    ("High|Critical|Unknown", "Critical"),
    ("High|High|Yes", "Critical"),
    ("High|High|No", "High"),
    ("High|High|Unknown", "High"),
    ("High|Medium|Yes", "Critical"),
    ("High|Medium|No", "High"),
    ("High|Medium|Unknown", "High"),
    ("High|Low|Yes", "High"),
    ("High|Low|No", "Medium"),
    ("High|Low|Unknown", "Medium"),
    ("High|Information|Yes", "Medium"),
    ("High|Information|No", "Low"),
    ("High|Information|Unknown", "Low"),
    ("Medium|Critical|Yes", "Critical"),
    ("Medium|Critical|No", "High"),
    ("Medium|Critical|Unknown", "High"),
    ("Medium|High|Yes", "Critical"),
    ("Medium|High|No", "High"),
    ("Medium|High|Unknown", "High"),
    ("Medium|Medium|Yes", "High"),
    ("Medium|Medium|No", "Medium"),
    ("Medium|Medium|Unknown", "Medium"),
    ("Medium|Low|Yes", "Medium"),
    ("Medium|Low|No", "Low"),
    ("Medium|Low|Unknown", "Low"),
    ("Medium|Information|Yes", "Low"),
    ("Medium|Information|No", "Information"),
    ("Medium|Information|Unknown", "Information"),
    ("Low|Critical|Yes", "High"),
    ("Low|Critical|No", "Medium"),
    ("Low|Critical|Unknown", "Medium"),
    ("Low|High|Yes", "High"),
    ("Low|High|No", "Medium"),
    ("Low|High|Unknown", "Medium"),
    ("Low|Medium|Yes", "Medium"),
    ("Low|Medium|No", "Low"),
    ("Low|Medium|Unknown", "Low"),
    ("Low|Low|Yes", "Low"),
    ("Low|Low|No", "Low"),
    ("Low|Low|Unknown", "Low"),
    ("Low|Information|Yes", "Low"),
    ("Low|Information|No", "Information"),
    ("Low|Information|Unknown", "Information"),
]
for i, (k, v) in enumerate(matrix, start=2):
    lk.cell(row=i, column=1, value=k)
    lk.cell(row=i, column=2, value=v)
lk.column_dimensions["A"].width = 34
lk.column_dimensions["B"].width = 26
n_matrix = len(matrix)

# ---------------------------------------------------------------------------
# SLA sheet: Actual Risk Classification -> days to fix
# ---------------------------------------------------------------------------
sla = wb.create_sheet("FixWindow")
sla["A1"] = "Actual Risk Classification"
sla["B1"] = "Fix Window (Days)"
for cell in ("A1", "B1"):
    sla[cell].font = Font(name="Arial", bold=True, color="FFFFFF")
    sla[cell].fill = HEADER_FILL
sla_rows = [
    ("Critical", 30),
    ("High", 60),
    ("Medium", 90),
    ("Low", 120),
    ("Information", ""),  # no forced SLA
]
for i, (k, v) in enumerate(sla_rows, start=2):
    sla.cell(row=i, column=1, value=k)
    sla.cell(row=i, column=2, value=v)
sla.column_dimensions["A"].width = 26
sla.column_dimensions["B"].width = 12
sla["D1"] = "Information findings have no forced Target Fix Date (discretionary)."
sla["D1"].font = Font(name="Arial", italic=True, size=9)

# ---------------------------------------------------------------------------
# Asset Owners sheet (editable list that feeds the dropdown)
# ---------------------------------------------------------------------------
own = wb.create_sheet("AssetOwners")
own["A1"] = "Asset Owner"
own["A1"].font = Font(name="Arial", bold=True, color="FFFFFF")
own["A1"].fill = HEADER_FILL
example_owners = ["Gati", "Network Team", "Systems Team", "Security Team", "Unassigned"]
for i, name in enumerate(example_owners, start=2):
    own.cell(row=i, column=1, value=name)
own.column_dimensions["A"].width = 26
own["C1"] = "Add owners down column A. New names appear in the Asset Owner dropdown automatically (up to row 200)."
own["C1"].font = Font(name="Arial", italic=True, size=9)

# ---------------------------------------------------------------------------
# Lists sheet: dropdown option lists
# ---------------------------------------------------------------------------
lists = wb.create_sheet("Lists")
lists["A1"] = "Risk Ratings"
lists["B1"] = "Exploit Available"
lists["C1"] = "Remediation Status"
lists["D1"] = "Yes/No"
for c in ("A1", "B1", "C1", "D1"):
    lists[c].font = Font(name="Arial", bold=True, color="FFFFFF")
    lists[c].fill = HEADER_FILL

risk_ratings = ["Critical", "High", "Medium", "Low", "Information"]
exploit_opts = ["Yes", "No", "Unknown"]
remediation_opts = ["Pending", "Reported", "In progress", "On hold", "Testing",
                    "Fixed", "Not Applicable", "Risk Accepted", "Exception Approved"]
yesno = ["Yes", "No"]
for i, v in enumerate(risk_ratings, start=2):
    lists.cell(row=i, column=1, value=v)
for i, v in enumerate(exploit_opts, start=2):
    lists.cell(row=i, column=2, value=v)
for i, v in enumerate(remediation_opts, start=2):
    lists.cell(row=i, column=3, value=v)
for i, v in enumerate(yesno, start=2):
    lists.cell(row=i, column=4, value=v)
for col in ("A", "B", "C", "D"):
    lists.column_dimensions[col].width = 20

# ---------------------------------------------------------------------------
# Data rows: formulas for every automated column.
# We lay down formulas for rows 2..(MAXROW). Row 2 = worked example.
# ---------------------------------------------------------------------------
MAXROW = 500  # findings capacity

for r in range(2, MAXROW + 1):
    # K: Actual Risk Classification = INDEX/MATCH on RiskMatrix by C|I|J
    # Guard: blank if any of C, I, J blank.
    k_formula = (
        f'=IF(OR($C{r}="",$I{r}="",$J{r}=""),"",'
        f'IFERROR(INDEX(RiskMatrix!$B$2:$B${n_matrix+1},'
        f'MATCH($C{r}&"|"&$I{r}&"|"&$J{r},RiskMatrix!$A$2:$A${n_matrix+1},0)),""))'
    )
    ws.cell(row=r, column=11, value=k_formula)

    # P: Target Fix Date = Detection Date + SLA days (by Actual Risk Classification K)
    # Information => no forced date (blank). If exception approved w/ revised date, that is
    # shown separately in W; P stays the original SLA target.
    p_formula = (
        f'=IF(OR($O{r}="",$K{r}=""),"",'
        f'IFERROR(IF(INDEX(FixWindow!$B$2:$B$6,MATCH($K{r},FixWindow!$A$2:$A$6,0))="","",'
        f'$O{r}+INDEX(FixWindow!$B$2:$B$6,MATCH($K{r},FixWindow!$A$2:$A$6,0))),""))'
    )
    ws.cell(row=r, column=16, value=p_formula)

    # Q: Time to Fix (Days) = P - O (the SLA window length)
    q_formula = f'=IF(OR($P{r}="",$O{r}=""),"",$P{r}-$O{r})'
    ws.cell(row=r, column=17, value=q_formula)

    # S: Actual Fix Date — auto-stamp the date the row was marked Fixed/Not Applicable,
    # but remain editable. Because a formula can't be "editable after it fires", we use a
    # helper: if the user hasn't typed a date, and status is Fixed/NA, show TODAY() captured
    # as a static value is impossible in pure formula. So: we leave S as INPUT, and provide a
    # one-click behaviour in the web app. In the spreadsheet, S shows a suggested date via a
    # comment and conditional note. We keep S as a plain input cell here.
    # (Handled as input; see note below.)

    # T: Risk Tolerance Objective
    #   - If Remediation Status in (Not Applicable, Risk Accepted, Exception Approved) => Not Applicable
    #   - Else if Actual Fix Date blank => blank (not yet resolved)
    #   - Else compare Actual Fix Date to effective target (Revised Target Fix Date if present else P)
    #       <= target => Met ; > target => Breached
    #   - If Information (no target date) and fixed => Met (no SLA to breach)
    t_formula = (
        f'=IF(OR($R{r}="Not Applicable",$R{r}="Risk Accepted",$R{r}="Exception Approved"),"Not Applicable",'
        f'IF($S{r}="","",'
        f'IF(IF($W{r}<>"",$W{r},$P{r})="","Met",'
        f'IF($S{r}<=IF($W{r}<>"",$W{r},$P{r}),"Met","Breached"))))'
    )
    ws.cell(row=r, column=20, value=t_formula)

    # Apply fills / borders / alignment per row
    for col_idx in range(1, len(headers) + 1):
        cell = ws.cell(row=r, column=col_idx)
        cell.border = BORDER
        cell.alignment = WRAP
        cell.font = Font(name="Arial", size=10)
        col_letter = get_column_letter(col_idx)
        if col_letter in AUTO_COLS:
            cell.fill = AUTO_FILL

# Date number format for date columns
for col_letter in ("O", "P", "S", "W"):
    for r in range(2, MAXROW + 1):
        ws[f"{col_letter}{r}"].number_format = "mmm dd, yyyy"

# ---------------------------------------------------------------------------
# Data validation (dropdowns)
# ---------------------------------------------------------------------------
def add_dv(formula, col, allow_blank=True):
    dv = DataValidation(type="list", formula1=formula, allow_blank=allow_blank)
    dv.add(f"{col}2:{col}{MAXROW}")
    ws.add_data_validation(dv)

add_dv("=Lists!$A$2:$A$6", "C")   # Asset Classification
add_dv("=Lists!$A$2:$A$6", "I")   # Reported Risk Rating
add_dv("=Lists!$B$2:$B$4", "J")   # Exploit Available
add_dv("=Lists!$C$2:$C$10", "R")  # Remediation Status
add_dv("=Lists!$D$2:$D$3", "U")   # Exception Requested?
add_dv("=AssetOwners!$A$2:$A$200", "N")  # Asset Owner (editable list)

# ---------------------------------------------------------------------------
# Worked example row (row 2), matching the user's sample. Yellow = example.
# ---------------------------------------------------------------------------
import datetime
example = {
    "A": "10.100.72.3",
    "B": "Unifi Dream Machine",
    "C": "Critical",
    "D": "Operating System (OS) End of Life (EOL) Detection",
    "E": ("The scan detected that the host is running Debian GNU/Linux 11, an operating "
          "system version that has reached its End of Life (EOL) as of 2026-08-31. "
          "QoD (Quality of Detection): 80%."),
    "F": ("The operating system on this server is no longer supported by its vendor (Debian). "
          "Debian will no longer release security patches for newly discovered vulnerabilities "
          "in this OS version. Any new security flaw found in Debian 11 from now on will never "
          "be fixed on this machine unless it is manually upgraded."),
    "G": "N/A — EOL/lifecycle detection covering the OS as a whole, not a single CVE",
    "H": ("Because Debian 11 no longer receives security updates, this host is exposed to any "
          "vulnerability discovered in the OS going forward, with no vendor fix coming. Over time "
          "this host becomes an increasingly easy and silent entry point for attackers."),
    "I": "Critical",
    "J": "No",
    # K auto
    "L": ("Not an exploit in itself. Risk stems from future unpatched CVEs that will never be "
          "fixed on this EOL version."),
    "M": ("Upgrade the OS to a currently supported Debian release (e.g. Debian 12/13) or migrate "
          "the service to a supported distribution. If immediate upgrade isn't possible, isolate "
          "the host from untrusted networks and monitor closely until migration."),
    "N": "Gati",
    "O": datetime.datetime(2026, 9, 14),
    # P, Q auto
    "R": "Not Applicable",
    "S": datetime.datetime(2026, 9, 22),
    # T auto
    "U": "No",
    "V": "",
    "W": "",
    "X": ("The version of Bullseye is being maintained by UniFi. "
          "https://community.ui.com/questions/UniFi-Dream-Machine-Pro-Max-Debian-11-11-EOL-8-31-26/"),
    "Y": "Remediate immediately to prevent exploitation of an unsupported/unpatched OS.",
}
for col, val in example.items():
    ws[f"{col}2"] = val
    ws[f"{col}2"].fill = EXAMPLE_FILL
# keep auto columns in example shaded green but note example via comment
ws["A2"].comment = Comment("EXAMPLE ROW — replace with real findings or delete. "
                           "Green columns (K, P, Q, T) are calculated automatically.", "VAPT Template")

# ---------------------------------------------------------------------------
# Legend / instructions sheet
# ---------------------------------------------------------------------------
leg = wb.create_sheet("README", 0)  # make it the first sheet
leg.sheet_view.showGridLines = False
leg.column_dimensions["A"].width = 100
title_font = Font(name="Arial", bold=True, size=16, color="1F4E78")
h2 = Font(name="Arial", bold=True, size=12, color="1F4E78")
body = Font(name="Arial", size=10)
leg["A1"] = "Quarterly VAPT Assessment — Report Template"
leg["A1"].font = title_font
notes = [
    "",
    ("HOW TO USE", h2),
    ("1. Run your scans with your trusted engines (Nessus / OpenVAS / Nmap). This workbook is "
     "for recording, classifying and tracking the findings — it does not scan.", body),
    ("2. Enter one finding per row on the 'Findings' sheet. Fill the WHITE columns. "
     "The GREEN columns calculate themselves — do not type in them.", body),
    ("3. Row 2 on 'Findings' is a worked example (yellow). Replace or delete it.", body),
    ("", body),
    ("WHAT IS AUTOMATED (green columns)", h2),
    ("• Actual Risk Classification — looked up from Asset Classification + Reported Risk Rating "
     "+ Exploit Available, using the matrix on the 'RiskMatrix' sheet.", body),
    ("• Target Fix Date — Detection Date + fix window: Critical +30, High +60, Medium +90, Low +120 days. "
     "Information has no forced date (your discretion). The window table is on the 'FixWindow' sheet.", body),
    ("• Time to Fix (Days) — the fix-window length (Target Fix Date − Detection Date).", body),
    ("• Risk Tolerance Objective — 'Met' if the Actual Fix Date is on/before the effective target "
     "(Revised Target Fix Date if an exception was approved, otherwise Target Fix Date); 'Breached' "
     "if later; 'Not Applicable' if status is Not Applicable / Risk Accepted / Exception Approved.", body),
    ("", body),
    ("WHAT YOU EDIT BY HAND", h2),
    ("• Detection Date — the day the scan ran / report was generated.", body),
    ("• Remediation Status — dropdown: Pending, Reported, In progress, On hold, Testing, Fixed, "
     "Not Applicable, Risk Accepted, Exception Approved.", body),
    ("• Actual Fix Date — the day it was actually fixed. (In the web app this auto-stamps the day "
     "you set status to Fixed/Not Applicable, and stays editable. In the spreadsheet, type it in.)", body),
    ("• Exception Requested? / Exception Approved By / Revised Target Fix Date — fill these when an "
     "exception is raised; the Risk Tolerance Objective then measures against the revised date.", body),
    ("• Asset Owner — dropdown fed by the 'AssetOwners' sheet. Add owners there and they appear in "
     "the dropdown automatically.", body),
    ("", body),
    ("NOTE ON THE RISK MATRIX", h2),
    ("The matrix reproduces the logic from your original XLOOKUP formula, re-expressed with "
     "INDEX/MATCH so it stays reliable across Excel and LibreOffice. If you want to change how a "
     "combination is rated, edit column B on the 'RiskMatrix' sheet — the whole workbook updates.", body),
]
row = 2
for item in notes:
    if isinstance(item, tuple):
        text, font = item
    else:
        text, font = item, body
    leg[f"A{row}"] = text
    leg[f"A{row}"].font = font
    leg[f"A{row}"].alignment = Alignment(wrap_text=True, vertical="top")
    row += 1

wb.save("/home/claude/VAPT_Report_Template.xlsx")
print("Saved VAPT_Report_Template.xlsx")
print(f"Matrix rows: {n_matrix} (expected 60)")
