"""
Nmap XML parser (-oX output).

Nmap is primarily a discovery/port scanner, so most findings it yields are
open-service inventory (Information) plus anything its NSE vuln scripts flag.
We produce:
  - one Information finding per open port/service (so the analyst has the attack
    surface recorded), and
  - a finding per NSE script that looks vulnerability-related (vuln*, ssl-*,
    http-* with CVE output, etc.), lifted to a higher band when it reports a CVE
    or a 'VULNERABLE' state.
"""
import xml.etree.ElementTree as ET
from .common import extract_cves, clean

# NSE scripts that usually carry real findings rather than banners.
_VULN_SCRIPT_HINTS = ("vuln", "ssl-", "smb-vuln", "http-vuln", "ftp-", "ssh-")


def parse_nmap_xml(raw_bytes):
    root = ET.fromstring(raw_bytes)
    findings = []

    for host in root.findall("host"):
        # address: prefer IPv4
        ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                if addr.get("addrtype") == "ipv4":
                    break
        # hostname
        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        display_host = ip or hostname
        # OS guess
        os_name = ""
        osmatch = host.find("os/osmatch")
        if osmatch is not None:
            os_name = osmatch.get("name", "")

        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = port.get("portid", "")
            proto = port.get("protocol", "")
            svc = port.find("service")
            svc_name = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            banner = " ".join(filter(None, [product, version]))

            # Base inventory finding (Information)
            findings.append({
                "ip_hostname": clean(display_host),
                "device": clean(os_name),
                "vulnerability": clean(f"Open port {portid}/{proto} — {svc_name or 'service'}"),
                "synopsis": clean(f"Open {proto} port {portid} running {svc_name or 'unknown service'}"
                                  + (f" ({banner})" if banner else "")),
                "definition": clean("Nmap detected this port open during discovery. Recorded as "
                                    "attack-surface inventory; confirm the service is required and hardened."),
                "cve": "",
                "reported_risk": "Information",
                "exploit_available": "Unknown",
                "exploit_reference": "",
                "solution": clean("Close the port if the service is not required, or restrict access by "
                                  "firewall/segmentation and keep the service patched."),
                "source_tool": "Nmap",
            })

            # NSE script findings on this port
            for script in port.findall("script"):
                sid = script.get("id", "")
                output = script.get("output", "") or ""
                low_id = sid.lower()
                if not any(h in low_id for h in _VULN_SCRIPT_HINTS):
                    continue
                cves = extract_cves(output, sid)
                is_vuln = "VULNERABLE" in output.upper() or bool(cves)
                band = "High" if is_vuln else "Information"
                findings.append({
                    "ip_hostname": clean(display_host),
                    "device": clean(os_name),
                    "vulnerability": clean(f"{sid} on {portid}/{proto}"),
                    "synopsis": clean(output[:300]),
                    "definition": clean(output),
                    "cve": cves,
                    "reported_risk": band,
                    "exploit_available": "Unknown",
                    "exploit_reference": "",
                    "solution": clean("Review the NSE script output and apply the vendor fix for the "
                                      "referenced issue; verify with a focused re-scan."),
                    "source_tool": "Nmap NSE",
                })

        # host-level NSE scripts (e.g. smb-vuln run at host scope)
        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                sid = script.get("id", "")
                output = script.get("output", "") or ""
                cves = extract_cves(output, sid)
                is_vuln = "VULNERABLE" in output.upper() or bool(cves)
                if not (any(h in sid.lower() for h in _VULN_SCRIPT_HINTS) or is_vuln):
                    continue
                findings.append({
                    "ip_hostname": clean(display_host),
                    "device": clean(os_name),
                    "vulnerability": clean(f"{sid} (host)"),
                    "synopsis": clean(output[:300]),
                    "definition": clean(output),
                    "cve": cves,
                    "reported_risk": "High" if is_vuln else "Information",
                    "exploit_available": "Unknown",
                    "exploit_reference": "",
                    "solution": clean("Apply the vendor patch for the referenced vulnerability and re-scan to confirm."),
                    "source_tool": "Nmap NSE",
                })
    return findings
