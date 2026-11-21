"""
compliance.py — map findings to control frameworks.

An informational overlay: it relates each finding, by the nature of the weakness,
to the control(s) that address it in each framework the user has enabled, so an
assessor can see which control areas have open gaps. Guidance for assessment, not
a certification of compliance.

Frameworks are selectable (Settings): the user ticks the ones relevant to their
environment. Matching is conservative keyword/regex over the finding text; a
finding can touch several controls and several frameworks.
"""
import re

# --- the catalogue of selectable frameworks --------------------------------
FRAMEWORKS = [
    {"id": "iso27001", "name": "ISO/IEC 27001:2022 (ISMS)",
     "desc": "Annex A controls — the information-security management standard."},
    {"id": "pci", "name": "PCI DSS v4.0",
     "desc": "Payment Card Industry Data Security Standard requirements."},
    {"id": "nistcsf", "name": "NIST CSF 2.0",
     "desc": "NIST Cybersecurity Framework functions and categories."},
    {"id": "cis", "name": "CIS Controls v8",
     "desc": "Center for Internet Security prioritised safeguards."},
    {"id": "soc2", "name": "SOC 2 (Trust Services Criteria)",
     "desc": "AICPA security/availability/confidentiality criteria."},
    {"id": "nist80053", "name": "NIST SP 800-53 Rev.5",
     "desc": "US federal security and privacy control catalogue."},
    {"id": "gdpr", "name": "GDPR (Art. 32 security)",
     "desc": "EU data-protection 'security of processing' obligations."},
    {"id": "hipaa", "name": "HIPAA Security Rule",
     "desc": "US healthcare technical safeguards (45 CFR §164.312)."},
]
FRAMEWORK_BY_ID = {f["id"]: f for f in FRAMEWORKS}
DEFAULT_ENABLED = ["iso27001", "pci"]

# --- weakness categories -> controls per framework -------------------------
# Each category: a regex over the finding text and the control(s) it implies in
# every framework. Control IDs are the public identifiers from each standard.
CATEGORIES = [
    {   # cryptography in transit — TLS, ciphers, certificates
        "pattern": r"\b(tls|ssl|cipher|certificate|cert|forward secrecy|https|openssl)\b",
        "controls": {
            "iso27001": [("8.24", "Use of cryptography")],
            "pci": [("4.2", "Strong cryptography for transmission")],
            "nistcsf": [("PR.DS-02", "Data-in-transit is protected")],
            "cis": [("3.10", "Encrypt sensitive data in transit")],
            "soc2": [("CC6.7", "Data in transit is protected")],
            "nist80053": [("SC-8", "Transmission confidentiality & integrity")],
            "gdpr": [("Art. 32(1)(a)", "Encryption of personal data")],
            "hipaa": [("§164.312(e)", "Transmission security")],
        }},
    {   # technical vulnerabilities / patching / outdated software
        "pattern": r"\b(cve-|outdated|version|unpatched|eol|end of life|bluekeep|eternalblue|smbv1|legacy)\b",
        "controls": {
            "iso27001": [("8.8", "Management of technical vulnerabilities")],
            "pci": [("6.3", "Security vulnerabilities are identified & addressed")],
            "nistcsf": [("ID.RA-01", "Vulnerabilities are identified & recorded")],
            "cis": [("7.1", "Continuous vulnerability management")],
            "soc2": [("CC7.1", "Vulnerabilities are detected & monitored")],
            "nist80053": [("RA-5", "Vulnerability monitoring & scanning")],
            "gdpr": [("Art. 32(1)(d)", "Regular testing of security measures")],
            "hipaa": [("§164.308(a)(1)", "Security management / risk")],
        }},
    {   # secure configuration / hardening
        "pattern": r"\b(header|hsts|x-frame|content-security|cookie|signing|nla|directory listing|"
                   r"trace|method|disclosure|banner|default|hardening|snmp)\b",
        "controls": {
            "iso27001": [("8.9", "Configuration management")],
            "pci": [("2.2", "System components are configured securely")],
            "nistcsf": [("PR.PS-01", "Configuration management is established")],
            "cis": [("4.1", "Secure configuration of enterprise assets")],
            "soc2": [("CC6.1", "Logical access & secure configuration")],
            "nist80053": [("CM-6", "Configuration settings")],
            "gdpr": [("Art. 32(1)(b)", "Ensure confidentiality, integrity, availability")],
            "hipaa": [("§164.308(a)(5)", "Security awareness & procedures")],
        }},
    {   # network exposure / segmentation / open services
        "pattern": r"\b(exposed|open service|open port|reachable|segment|rdp|smb|redis|mongodb|"
                   r"elasticsearch|memcached|database port)\b",
        "controls": {
            "iso27001": [("8.20", "Networks security"), ("8.22", "Segregation of networks")],
            "pci": [("1.3", "Network access to the CDE is restricted")],
            "nistcsf": [("PR.IR-01", "Networks are protected from unauthorized access")],
            "cis": [("12.2", "Establish & maintain a secure network architecture")],
            "soc2": [("CC6.6", "Logical access boundaries restrict access")],
            "nist80053": [("SC-7", "Boundary protection")],
            "gdpr": [("Art. 32(1)(b)", "Ensure confidentiality, integrity, availability")],
            "hipaa": [("§164.312(a)(1)", "Access control")],
        }},
    {   # cleartext / insecure transfer protocols
        "pattern": r"\b(telnet|ftp|cleartext|plaintext|unencrypted|vnc|http method|http trace)\b",
        "controls": {
            "iso27001": [("5.14", "Information transfer")],
            "pci": [("4.2", "Strong cryptography for transmission")],
            "nistcsf": [("PR.DS-02", "Data-in-transit is protected")],
            "cis": [("3.10", "Encrypt sensitive data in transit")],
            "soc2": [("CC6.7", "Data in transit is protected")],
            "nist80053": [("SC-8", "Transmission confidentiality & integrity")],
            "gdpr": [("Art. 32(1)(a)", "Encryption of personal data")],
            "hipaa": [("§164.312(e)", "Transmission security")],
        }},
    {   # authentication / access
        "pattern": r"\b(authentication|nla|network level authentication|credential|anonymous|null session|"
                   r"unauthenticated|default password)\b",
        "controls": {
            "iso27001": [("8.5", "Secure authentication")],
            "pci": [("8.3", "Strong authentication for users & admins")],
            "nistcsf": [("PR.AA-03", "Users and devices are authenticated")],
            "cis": [("6.3", "Require MFA / strong authentication")],
            "soc2": [("CC6.1", "Logical access security")],
            "nist80053": [("IA-2", "Identification & authentication")],
            "gdpr": [("Art. 32(1)(b)", "Ensure confidentiality, integrity, availability")],
            "hipaa": [("§164.312(d)", "Person or entity authentication")],
        }},
]

CONTROL_TITLES = {}
for _c in CATEGORIES:
    for _fw, _ctrls in _c["controls"].items():
        for _cid, _ct in _ctrls:
            CONTROL_TITLES[(_fw, _cid)] = _ct

SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Information": 0, "": 0, None: 0}


def _finding_text(finding):
    return " ".join(str(finding.get(k, "") or "") for k in
                    ("vulnerability", "synopsis", "definition", "cve")).lower()


def map_finding(finding, enabled=None):
    """Return {framework_name: [(control_id, title), ...]} for one finding."""
    enabled = enabled or [f["id"] for f in FRAMEWORKS]
    text = _finding_text(finding)
    hits = {}
    seen = set()
    for cat in CATEGORIES:
        if not re.search(cat["pattern"], text):
            continue
        for fwid in enabled:
            name = FRAMEWORK_BY_ID.get(fwid, {}).get("name")
            if not name:
                continue
            for cid, title in cat["controls"].get(fwid, []):
                if (fwid, cid) not in seen:
                    seen.add((fwid, cid))
                    hits.setdefault(name, []).append((cid, title))
    return hits


def coverage(findings, enabled=None):
    """Per-framework coverage. Returns {framework_name: [ {id,title,count,open,max_sev,finding_ids} ]}."""
    enabled = enabled or DEFAULT_ENABLED
    names = [FRAMEWORK_BY_ID[i]["name"] for i in enabled if i in FRAMEWORK_BY_ID]
    frameworks = {n: {} for n in names}
    for f in findings:
        status = (f.get("remediation_status") or "")
        is_open = status not in ("Fixed", "Not Applicable")
        sev = f.get("actual_risk_classification") or f.get("reported_risk") or ""
        for name, ctrls in map_finding(f, enabled).items():
            for cid, title in ctrls:
                slot = frameworks[name].setdefault(
                    cid, {"id": cid, "title": title, "count": 0, "open": 0,
                          "max_sev": "", "max_rank": -1, "finding_ids": []})
                slot["count"] += 1
                if is_open:
                    slot["open"] += 1
                if SEV_RANK.get(sev, 0) > slot["max_rank"]:
                    slot["max_rank"] = SEV_RANK.get(sev, 0)
                    slot["max_sev"] = sev
                slot["finding_ids"].append(f.get("id"))
    out = {}
    for name, slots in frameworks.items():
        out[name] = sorted(slots.values(), key=lambda s: (-s["max_rank"], -s["open"], s["id"]))
    return out


if __name__ == "__main__":
    sample = [
        {"id": 1, "vulnerability": "Legacy TLS 1.0 enabled", "reported_risk": "High",
         "actual_risk_classification": "High", "remediation_status": "Pending"},
        {"id": 2, "vulnerability": "SMBv1 protocol enabled", "cve": "CVE-2017-0144",
         "actual_risk_classification": "Critical", "remediation_status": "Fixed"},
    ]
    cov = coverage(sample, ["iso27001", "nistcsf", "cis", "hipaa"])
    assert "NIST CSF 2.0" in cov and "CIS Controls v8" in cov, list(cov)
    assert any(c["id"] == "8.24" for c in cov["ISO/IEC 27001:2022 (ISMS)"])
    m = map_finding(sample[0], ["hipaa"])
    assert "HIPAA Security Rule" in m, m
    print("compliance self-tests passed")
