# Standalone Excel report template

`build_template.py` generates `VAPT_Report_Template.xlsx` — the VAPT report with
every column and all the automation baked in, usable on its own without the app.

```bash
pip install openpyxl
python build_template.py
```

The template reproduces the app's logic in live spreadsheet formulas
(INDEX/MATCH, reliable in both Excel and LibreOffice):

- **Actual Risk Classification** — looked up from Asset Classification × Reported
  Risk Rating × Exploit Available (the 60-row matrix on the `RiskMatrix` sheet).
- **Target Fix Date** — Detection Date + fix window (Critical +30, High +60,
  Medium +90, Low +120 days; Information none). Window table on the `FixWindow`
  sheet.
- **Time to Fix (Days)** — the fix-window length.
- **Risk Tolerance Objective** — Met / Breached / Not Applicable, measured against
  the revised target date when an exception is approved.

Green columns calculate themselves; fill the white ones. Row 2 is a worked
example. See the `README` sheet inside the workbook for the in-file guide.
