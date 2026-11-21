"""Shared helpers for parsers: severity mapping, exploit detection, CVE extraction."""
import re

# Map scanner severities to our 5 bands.
_SEV_WORD = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "info": "Information",
    "informational": "Information",
    "information": "Information",
    "none": "Information",
    "log": "Information",
}

def map_severity_word(word):
    if word is None:
        return None
    return _SEV_WORD.get(str(word).strip().lower())


def map_cvss_to_band(score):
    """CVSS base score -> band. Follows the common Nessus/CVSSv3 cut-offs."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    if s > 0.0:
        return "Low"
    return "Information"


def nessus_risk_factor_to_band(rf):
    """Nessus 'risk_factor' field: Critical/High/Medium/Low/None."""
    return map_severity_word(rf)


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def extract_cves(*texts):
    found = []
    for t in texts:
        if not t:
            continue
        for m in _CVE_RE.findall(t):
            mu = m.upper()
            if mu not in found:
                found.append(mu)
    return ", ".join(found)


def exploit_available_from(*flags_and_texts):
    """
    Decide Yes/No/Unknown from scanner exploitability hints.
    Nessus gives 'exploit_available' = true/false and frameworks like metasploit.
    If nothing says either way, return 'Unknown'.
    """
    saw_true = False
    saw_false = False
    for v in flags_and_texts:
        if v is None:
            continue
        s = str(v).strip().lower()
        if s in ("true", "yes", "1"):
            saw_true = True
        elif s in ("false", "no", "0"):
            saw_false = True
        elif "metasploit" in s or "exploit-db" in s or "exploithub" in s or "canvas" in s or "core impact" in s:
            saw_true = True
    if saw_true:
        return "Yes"
    if saw_false:
        return "No"
    return "Unknown"


def clean(text):
    if text is None:
        return ""
    return " ".join(str(text).split())
