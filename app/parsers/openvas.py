"""OpenVAS / Greenbone parsers: GMP XML report and CSV export."""
import csv
import io
import xml.etree.ElementTree as ET
from .common import (
    map_cvss_to_band, map_severity_word, extract_cves,
    exploit_available_from, clean,
)


def parse_openvas_xml(raw_bytes):
    """
    Parse a Greenbone/OpenVAS GMP report export. Structure (simplified):
      <report> ... <results> <result>
          <host>10.0.0.1</host>
          <name>...</name>
          <severity>7.5</severity>
          <threat>High</threat>
          <nvt oid=...><name>..</name><cvss_base>7.5</cvss_base>
             <tags>summary=...|solution=...|insight=...</tags>
             <refs><ref type="cve" id="CVE-..."/></refs>
          </nvt>
          <description>...</description>
      </result>
    QoD lives in <qod><value>80</value></qod>.
    """
    root = ET.fromstring(raw_bytes)
    findings = []

    # results can be nested under report/report/results depending on export
    for result in root.iter("result"):
        host_el = result.find("host")
        host = host_el.text if host_el is not None else ""
        name_el = result.find("name")
        name = name_el.text if name_el is not None else ""
        threat_el = result.find("threat")
        threat = threat_el.text if threat_el is not None else None
        sev_el = result.find("severity")
        severity = sev_el.text if sev_el is not None else None
        desc_el = result.find("description")
        description = desc_el.text if desc_el is not None else ""

        qod = ""
        qod_el = result.find("qod")
        if qod_el is not None:
            qv = qod_el.find("value")
            if qv is not None and qv.text:
                qod = qv.text

        nvt = result.find("nvt")
        summary = solution = insight = ""
        cvss_base = None
        cve_ids = []
        os_hint = ""
        if nvt is not None:
            cb = nvt.find("cvss_base")
            if cb is not None:
                cvss_base = cb.text
            tags_el = nvt.find("tags")
            if tags_el is not None and tags_el.text:
                for part in tags_el.text.split("|"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        k = k.strip().lower()
                        if k == "summary":
                            summary = v
                        elif k == "solution":
                            solution = v
                        elif k == "insight":
                            insight = v
            refs = nvt.find("refs")
            if refs is not None:
                for ref in refs.findall("ref"):
                    if (ref.get("type") or "").lower() == "cve":
                        cve_ids.append(ref.get("id", ""))

        band = (map_severity_word(threat)
                or map_cvss_to_band(severity)
                or map_cvss_to_band(cvss_base)
                or "Information")

        syn = summary or name
        if qod:
            syn = f"{syn} (QoD: {qod}%)".strip()

        findings.append({
            "ip_hostname": clean(host),
            "device": clean(os_hint),
            "vulnerability": clean(name),
            "synopsis": clean(syn),
            "definition": clean(insight or description or summary),
            "cve": extract_cves(" ".join(cve_ids), description, name),
            "reported_risk": band,
            "exploit_available": exploit_available_from(None),  # OpenVAS rarely states; Unknown
            "exploit_reference": "",
            "solution": clean(solution),
            "source_tool": "OpenVAS",
        })
    return findings


def parse_openvas_csv(raw_bytes):
    """
    Greenbone CSV export. Typical columns:
      IP, Hostname, Port, Port Protocol, CVSS, Severity, Solution Type, NVT Name,
      Summary, Specific Result, Solution, CVEs, Other References, QoD
    """
    text = raw_bytes.decode("utf-8", "ignore")
    reader = csv.DictReader(io.StringIO(text))

    def val(row, *names):
        for n in names:
            for k in row:
                if k and k.strip().lower() == n.lower():
                    return row[k]
        return ""

    findings = []
    for row in reader:
        ip = val(row, "IP", "Host", "IP Address")
        hostname = val(row, "Hostname", "DNS Name")
        severity = val(row, "Severity", "Threat")
        cvss = val(row, "CVSS", "CVSS Base")
        name = val(row, "NVT Name", "Name", "Vulnerability")
        summary = val(row, "Summary")
        specific = val(row, "Specific Result", "Specific Prognosis", "Result")
        solution = val(row, "Solution")
        cves = val(row, "CVEs", "CVE")
        qod = val(row, "QoD", "QoD (%)")
        band = map_severity_word(severity) or map_cvss_to_band(cvss) or "Information"
        syn = summary or name
        if qod:
            syn = f"{syn} (QoD: {qod}%)".strip()
        findings.append({
            "ip_hostname": clean(ip or hostname),
            "device": clean(hostname if ip else ""),
            "vulnerability": clean(name),
            "synopsis": clean(syn),
            "definition": clean(specific or summary),
            "cve": extract_cves(cves, summary, name),
            "reported_risk": band,
            "exploit_available": exploit_available_from(None),
            "exploit_reference": "",
            "solution": clean(solution),
            "source_tool": "OpenVAS",
        })
    return findings
