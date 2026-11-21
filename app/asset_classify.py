"""
asset_classify.py — normalise and classify imported assets, and decide scan
eligibility.

Two jobs:
  1. Normalise the criticality the user assigned (free text -> canonical band).
  2. Infer the asset *type* (IT / OT / IoT / BYOD / Personal / Network) from the
     hostname and description, and from that set a scan policy.

SAFETY — the OT interlock:
  Operational-technology / industrial-control gear (PLCs, SCADA, HMIs, RTUs,
  building-management systems, medical devices) can be disrupted or damaged by
  active scanning. Anything classified OT — or that the user has tagged OT — is
  marked "do-not-actively-scan": the scanner will inventory it passively but
  never actively probe it. IoT gear is "scan with caution". This module only
  *recommends*; the user can override the type, but the scan governance in the
  app always honours the final type.

All heuristics are conservative and explainable; the user reviews and can edit
every classification after import.
"""
import re

CRITICALITY = ["Critical", "High", "Medium", "Low", "Information"]
TYPES = ["IT", "Network", "OT", "IoT", "BYOD", "Personal", "Unknown"]

# scan policy per type
SCAN_POLICY = {
    "OT": "Do not actively scan",
    "IoT": "Scan with caution",
    "BYOD": "Scan with authorisation",
    "Personal": "Scan with authorisation",
    "IT": "Scan",
    "Network": "Scan",
    "Unknown": "Review before scanning",
}

_CRIT_MAP = {
    "critical": "Critical", "crit": "Critical", "c": "Critical", "5": "Critical", "very high": "Critical",
    "high": "High", "h": "High", "4": "High",
    "medium": "Medium", "med": "Medium", "moderate": "Medium", "m": "Medium", "3": "Medium",
    "low": "Low", "l": "Low", "2": "Low",
    "information": "Information", "informational": "Information", "info": "Information",
    "none": "Information", "1": "Information", "0": "Information",
}

# keyword -> type. Order matters: OT first (most safety-critical), then IoT, etc.
_TYPE_RULES = [
    ("OT", r"\b(plc|scada|hmi|rtu|dcs|ics|modbus|profibus|bacnet|ot[-_]?net|"
           r"controller|actuator|relay|substation|genset|ups[-_]?ctrl|bms|"
           r"building[-_ ]?mgmt|industrial|automation|fieldbus|opc)\b"),
    ("IoT", r"\b(cam|camera|cctv|ipcam|nvr|dvr|printer|mfp|scanner|badge|"
            r"door|access[-_ ]?control|hvac|thermostat|sensor|iot|smart[-_ ]?|"
            r"intercom|signage|kiosk|tv|display)\b"),
    ("Network", r"\b(sw|switch|rtr|router|fw|firewall|gw|gateway|ap|wap|wlc|"
                r"lb|loadbalancer|core|edge|dist|vpn|proxy)\b"),
    ("Personal", r"\b(personal|employee|staff[-_ ]?pc|home|byod[-_ ]?personal)\b"),
    ("BYOD", r"\b(byod|laptop|lap|notebook|macbook|mobile|phone|tablet|ipad|"
             r"workstation|wks|desktop|pc[-_ ]?user|user[-_ ]?pc)\b"),
    ("IT", r"\b(srv|server|svr|db|database|web|app|dc|domain|ad|dns|dhcp|mail|"
           r"smtp|exchange|file|backup|vm|host|esx|hyperv|nas|san|san[-_ ]?sw|"
           r"storage|san)\b"),
]


def normalise_criticality(value):
    if value is None:
        return ""
    s = str(value).strip().lower()
    if not s:
        return ""
    return _CRIT_MAP.get(s, _title_if_known(s))


def _title_if_known(s):
    t = s.title()
    return t if t in CRITICALITY else ""


def infer_type(hostname="", description="", hint=""):
    """Infer the asset type from any text we have. Returns (type, matched_keyword)."""
    text = " ".join(str(x or "") for x in (hostname, description, hint)).lower()
    for atype, pattern in _TYPE_RULES:
        m = re.search(pattern, text)
        if m:
            return atype, m.group(0)
    return "Unknown", ""


def classify(row):
    """
    row: dict with any of ip, hostname, description/asset, criticality, type.
    Returns a normalised asset dict with classification + scan policy + the
    reason, so the UI can show *why* something was tagged (especially OT).
    """
    ip = str(row.get("ip") or row.get("ip_hostname") or "").strip()
    hostname = str(row.get("hostname") or row.get("host") or "").strip()
    desc = str(row.get("description") or row.get("asset") or row.get("notes") or "").strip()
    owner = str(row.get("owner") or row.get("asset_owner") or "").strip()

    # criticality: user's value wins; else blank for them to fill
    crit = normalise_criticality(row.get("criticality") or row.get("asset_classification")
                                 or row.get("risk") or "")

    # type: explicit user tag wins; else infer
    user_type = str(row.get("type") or row.get("asset_type") or "").strip()
    reason = ""
    if user_type and user_type.upper() in [t.upper() for t in TYPES]:
        atype = next(t for t in TYPES if t.upper() == user_type.upper())
        reason = "set by import"
    else:
        atype, kw = infer_type(hostname, desc, ip)
        reason = f"matched '{kw}'" if kw else "no keyword matched — review"

    policy = SCAN_POLICY.get(atype, "Review before scanning")
    return {
        "ip": ip, "hostname": hostname, "description": desc, "owner": owner,
        "criticality": crit, "asset_type": atype, "scan_policy": policy,
        "classify_reason": reason,
        "scan_eligible": 0 if policy == "Do not actively scan" else 1,
    }


# column-name aliases accepted from an uploaded sheet (lowercased, stripped)
COLUMN_ALIASES = {
    "ip": ["ip", "ip address", "ip_address", "address", "ipaddr"],
    "hostname": ["hostname", "host", "host name", "name", "device", "asset name", "fqdn"],
    "description": ["description", "asset", "asset description", "notes", "comment", "purpose", "role"],
    "criticality": ["criticality", "asset classification", "classification", "risk", "priority", "importance", "tier"],
    "type": ["type", "asset type", "category", "class", "kind"],
    "owner": ["owner", "asset owner", "team", "custodian", "responsible"],
}


def map_headers(headers):
    """Map a sheet's header row to our canonical field names."""
    mapping = {}
    for idx, h in enumerate(headers):
        key = str(h or "").strip().lower()
        for canon, aliases in COLUMN_ALIASES.items():
            if key in aliases and canon not in mapping:
                mapping[canon] = idx
                break
    return mapping


if __name__ == "__main__":
    t, _ = infer_type("plc-line3", "Siemens S7 controller")
    assert t == "OT", t
    assert classify({"ip": "10.0.0.5", "hostname": "scada-hmi-1"})["scan_eligible"] == 0
    assert classify({"ip": "10.0.0.6", "hostname": "web-srv-1"})["asset_type"] == "IT"
    assert classify({"hostname": "cam-lobby"})["asset_type"] == "IoT"
    assert classify({"hostname": "jdoe-laptop"})["asset_type"] == "BYOD"
    assert normalise_criticality("crit") == "Critical"
    assert normalise_criticality("moderate") == "Medium"
    assert map_headers(["IP Address", "Host Name", "Criticality"]) == {"ip": 0, "hostname": 1, "criticality": 2}
    print("asset_classify self-tests passed")
