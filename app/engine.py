"""
engine.py — the automation logic shared by the whole app.

This is the single source of truth for:
  - the risk matrix (Asset Classification | Reported Risk | Exploit -> Actual Risk)
  - SLA days per Actual Risk Classification
  - Target Fix Date, Time to Fix
  - Risk Tolerance Objective (Met / Breached / Not Applicable)

It deliberately mirrors the Excel template so both artefacts agree to the day.
Pure Python, no dependencies, no network. Easy to audit.
"""
from datetime import date, timedelta

# Severity ordering (also the canonical spelling we store)
SEVERITIES = ["Critical", "High", "Medium", "Low", "Information"]
EXPLOIT_OPTIONS = ["Yes", "No", "Unknown"]

REMEDIATION_STATUSES = [
    "Pending", "Reported", "In progress", "On hold", "Testing",
    "Fixed", "Not Applicable", "Risk Accepted", "Exception Approved",
]
# Statuses that close a finding (stamp Actual Fix Date)
CLOSING_STATUSES = {"Fixed", "Not Applicable"}
# Statuses that make the Risk Tolerance Objective Not Applicable
RTO_NA_STATUSES = {"Not Applicable", "Risk Accepted", "Exception Approved"}

# SLA: Actual Risk Classification -> days to fix. Information = no forced SLA.
SLA_DAYS = {
    "Critical": 30,
    "High": 60,
    "Medium": 90,
    "Low": 120,
    "Information": None,
}

# ---------------------------------------------------------------------------
# Risk matrix: (asset_classification, reported_risk, exploit) -> actual_risk
# Transcribed from the client's XLOOKUP logic. 60 combinations.
# ---------------------------------------------------------------------------
_MATRIX_ROWS = [
    ("Critical", "Critical", "Yes", "Critical"),
    ("Critical", "Critical", "No", "Critical"),
    ("Critical", "Critical", "Unknown", "Critical"),
    ("Critical", "High", "Yes", "Critical"),
    ("Critical", "High", "No", "Critical"),
    ("Critical", "High", "Unknown", "Critical"),
    ("Critical", "Medium", "Yes", "Critical"),
    ("Critical", "Medium", "No", "High"),
    ("Critical", "Medium", "Unknown", "High"),
    ("Critical", "Low", "Yes", "High"),
    ("Critical", "Low", "No", "Medium"),
    ("Critical", "Low", "Unknown", "Medium"),
    ("Critical", "Information", "Yes", "Medium"),
    ("Critical", "Information", "No", "Low"),
    ("Critical", "Information", "Unknown", "Low"),
    ("High", "Critical", "Yes", "Critical"),
    ("High", "Critical", "No", "Critical"),
    ("High", "Critical", "Unknown", "Critical"),
    ("High", "High", "Yes", "Critical"),
    ("High", "High", "No", "High"),
    ("High", "High", "Unknown", "High"),
    ("High", "Medium", "Yes", "Critical"),
    ("High", "Medium", "No", "High"),
    ("High", "Medium", "Unknown", "High"),
    ("High", "Low", "Yes", "High"),
    ("High", "Low", "No", "Medium"),
    ("High", "Low", "Unknown", "Medium"),
    ("High", "Information", "Yes", "Medium"),
    ("High", "Information", "No", "Low"),
    ("High", "Information", "Unknown", "Low"),
    ("Medium", "Critical", "Yes", "Critical"),
    ("Medium", "Critical", "No", "High"),
    ("Medium", "Critical", "Unknown", "High"),
    ("Medium", "High", "Yes", "Critical"),
    ("Medium", "High", "No", "High"),
    ("Medium", "High", "Unknown", "High"),
    ("Medium", "Medium", "Yes", "High"),
    ("Medium", "Medium", "No", "Medium"),
    ("Medium", "Medium", "Unknown", "Medium"),
    ("Medium", "Low", "Yes", "Medium"),
    ("Medium", "Low", "No", "Low"),
    ("Medium", "Low", "Unknown", "Low"),
    ("Medium", "Information", "Yes", "Low"),
    ("Medium", "Information", "No", "Information"),
    ("Medium", "Information", "Unknown", "Information"),
    ("Low", "Critical", "Yes", "High"),
    ("Low", "Critical", "No", "Medium"),
    ("Low", "Critical", "Unknown", "Medium"),
    ("Low", "High", "Yes", "High"),
    ("Low", "High", "No", "Medium"),
    ("Low", "High", "Unknown", "Medium"),
    ("Low", "Medium", "Yes", "Medium"),
    ("Low", "Medium", "No", "Low"),
    ("Low", "Medium", "Unknown", "Low"),
    ("Low", "Low", "Yes", "Low"),
    ("Low", "Low", "No", "Low"),
    ("Low", "Low", "Unknown", "Low"),
    ("Low", "Information", "Yes", "Low"),
    ("Low", "Information", "No", "Information"),
    ("Low", "Information", "Unknown", "Information"),
]
RISK_MATRIX = {(a, r, e): actual for (a, r, e, actual) in _MATRIX_ROWS}


def actual_risk_classification(asset_classification, reported_risk, exploit):
    """Return the Actual Risk Classification, or None if inputs incomplete/unknown."""
    if not asset_classification or not reported_risk or not exploit:
        return None
    return RISK_MATRIX.get((asset_classification, reported_risk, exploit))


def target_fix_date(detection_date, actual_risk):
    """Detection Date + SLA days. Information (or missing SLA) -> None."""
    if not detection_date or not actual_risk:
        return None
    days = SLA_DAYS.get(actual_risk)
    if days is None:
        return None
    return detection_date + timedelta(days=days)


def time_to_fix_days(detection_date, tfd):
    if not detection_date or not tfd:
        return None
    return (tfd - detection_date).days


def risk_tolerance_objective(status, actual_fix_date, target_fix, revised_target):
    """
    Met / Breached / Not Applicable / None(unresolved).
      - status in RTO_NA_STATUSES -> Not Applicable
      - no actual fix date yet -> None (not resolved)
      - effective target = revised_target if present else target_fix
      - no effective target (Information) and fixed -> Met
      - actual_fix <= effective target -> Met else Breached
    """
    if status in RTO_NA_STATUSES:
        return "Not Applicable"
    if not actual_fix_date:
        return None
    effective = revised_target or target_fix
    if effective is None:
        return "Met"  # no SLA to breach
    return "Met" if actual_fix_date <= effective else "Breached"


def compute_row(row):
    """
    Given a dict with the stored input fields, return a dict of all derived fields.
    Dates in `row` are date objects or None.
    """
    actual = actual_risk_classification(
        row.get("asset_classification"),
        row.get("reported_risk"),
        row.get("exploit_available"),
    )
    tfd = target_fix_date(row.get("detection_date"), actual)
    ttf = time_to_fix_days(row.get("detection_date"), tfd)
    rto = risk_tolerance_objective(
        row.get("remediation_status"),
        row.get("actual_fix_date"),
        tfd,
        row.get("revised_target_fix_date"),
    )
    return {
        "actual_risk_classification": actual,
        "target_fix_date": tfd,
        "time_to_fix_days": ttf,
        "risk_tolerance_objective": rto,
    }


# --- self test -------------------------------------------------------------
if __name__ == "__main__":
    from datetime import date as d
    assert actual_risk_classification("Critical", "Critical", "No") == "Critical"
    assert actual_risk_classification("High", "High", "Yes") == "Critical"
    assert actual_risk_classification("Medium", "Low", "No") == "Low"
    assert target_fix_date(d(2026, 9, 14), "Critical") == d(2026, 10, 14)
    assert time_to_fix_days(d(2026, 9, 14), d(2026, 10, 14)) == 30
    assert risk_tolerance_objective("Not Applicable", d(2026, 9, 22), d(2026, 10, 14), None) == "Not Applicable"
    assert risk_tolerance_objective("Fixed", d(2026, 10, 1), d(2026, 10, 31), None) == "Met"
    assert risk_tolerance_objective("Fixed", d(2026, 12, 1), d(2026, 10, 1), None) == "Breached"
    assert risk_tolerance_objective("Fixed", d(2026, 12, 15), d(2026, 11, 30), d(2026, 12, 31)) == "Met"
    assert len(RISK_MATRIX) == 60
    print("engine self-test passed; matrix has", len(RISK_MATRIX), "entries")
