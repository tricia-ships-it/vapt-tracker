"""Nessus parsers: .nessus XML and CSV export."""
import csv
import io
import xml.etree.ElementTree as ET
from .common import (
    nessus_risk_factor_to_band, map_cvss_to_band, map_severity_word,
    extract_cves, exploit_available_from, clean,
)


def parse_nessus_xml(raw_bytes):
    """
    Parse a Tenable .nessus file. Structure:
      NessusClientData_v2 > Report > ReportHost(name=) > ReportItem(...)
    Each ReportItem is a finding on that host. severity 0..4 maps Info..Critical.
    """
    root = ET.fromstring(raw_bytes)
    findings = []
    sev_num = {"0": "Information", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}

    for report in root.iter("Report"):
        for host in report.findall("ReportHost"):
            hostname = host.get("name", "")
            # host properties may hold the resolved IP / fqdn / OS
            ip = hostname
            os_name = ""
            props = host.find("HostProperties")
            if props is not None:
                for tag in props.findall("tag"):
                    tname = tag.get("name", "")
                    if tname == "host-ip":
                        ip = tag.text or ip
                    elif tname in ("operating-system", "os"):
                        os_name = tag.text or os_name
            for item in host.findall("ReportItem"):
                # Skip the port-scan plugin noise? Keep everything; analyst filters.
                plugin_name = item.get("pluginName", "")
                severity = item.get("severity", "0")

                def gt(tag):
                    el = item.find(tag)
                    return el.text if el is not None else None

                risk_factor = gt("risk_factor")
                cvss3 = gt("cvss3_base_score")
                cvss2 = gt("cvss_base_score")
                synopsis = gt("synopsis")
                description = gt("description")
                solution = gt("solution")
                cve_text = " ".join([e.text or "" for e in item.findall("cve")])
                see_also = gt("see_also")
                exploit_flag = gt("exploit_available")
                exploit_frameworks = " ".join(filter(None, [
                    gt("exploit_framework_metasploit"),
                    gt("exploit_framework_core"),
                    gt("exploit_framework_canvas"),
                    gt("metasploit_name"),
                ]))

                # Determine reported band: prefer explicit risk_factor, then cvss, then severity num
                band = (nessus_risk_factor_to_band(risk_factor)
                        or map_cvss_to_band(cvss3)
                        or map_cvss_to_band(cvss2)
                        or sev_num.get(severity, "Information"))

                findings.append({
                    "ip_hostname": clean(ip),
                    "device": clean(os_name),
                    "vulnerability": clean(plugin_name),
                    "synopsis": clean(synopsis),
                    "definition": clean(description),
                    "cve": extract_cves(cve_text, description, plugin_name),
                    "reported_risk": band,
                    "exploit_available": exploit_available_from(exploit_flag, exploit_frameworks),
                    "exploit_reference": clean(exploit_frameworks or see_also),
                    "solution": clean(solution),
                    "source_tool": "Nessus",
                })
    return findings


def parse_nessus_csv(raw_bytes):
    """
    Parse a Nessus CSV export. Typical columns:
      Plugin ID, CVE, CVSS, Risk, Host, Protocol, Port, Name, Synopsis,
      Description, Solution, See Also, Plugin Output
    Header names vary slightly across versions; we match case-insensitively.
    """
    text = raw_bytes.decode("utf-8", "ignore")
    reader = csv.DictReader(io.StringIO(text))
    # normalise header keys
    def val(row, *names):
        for n in names:
            for k in row:
                if k and k.strip().lower() == n.lower():
                    return row[k]
        return ""

    findings = []
    for row in reader:
        host = val(row, "Host", "IP Address", "DNS Name")
        risk = val(row, "Risk", "Severity", "Risk Factor")
        cvss = val(row, "CVSS", "CVSS3 Base Score", "CVSS Base Score", "CVSSv3")
        band = map_severity_word(risk) or map_cvss_to_band(cvss) or "Information"
        name = val(row, "Name", "Plugin Name")
        synopsis = val(row, "Synopsis")
        desc = val(row, "Description")
        solution = val(row, "Solution")
        cve = val(row, "CVE")
        see_also = val(row, "See Also")
        metasploit = val(row, "Metasploit", "Exploit Available", "Exploitability Ease")
        findings.append({
            "ip_hostname": clean(host),
            "device": "",
            "vulnerability": clean(name),
            "synopsis": clean(synopsis),
            "definition": clean(desc),
            "cve": extract_cves(cve, desc, name),
            "reported_risk": band,
            "exploit_available": exploit_available_from(metasploit),
            "exploit_reference": clean(metasploit if "metasploit" in str(metasploit).lower() else see_also),
            "solution": clean(solution),
            "source_tool": "Nessus",
        })
    return findings
