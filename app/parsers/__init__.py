"""
Scan result parsers. Each returns a list of finding dicts with keys matching
the app's input fields. All parsing is offline; we never reach the network.

Supported:
  - Nessus .nessus (XML, Tenable)
  - Nessus CSV export
  - OpenVAS / Greenbone .xml (GMP report export)
  - OpenVAS / Greenbone CSV export
  - Nmap .xml (-oX), incl. basic vuln NSE script output

The parsers map the scanner's native severity to our 5-band scale and fill
as much of the report structure as the source provides. Unknown/blank fields
are left for the analyst to complete.
"""
from .nessus import parse_nessus_xml, parse_nessus_csv
from .openvas import parse_openvas_xml, parse_openvas_csv
from .nmap import parse_nmap_xml

__all__ = [
    "parse_nessus_xml", "parse_nessus_csv",
    "parse_openvas_xml", "parse_openvas_csv",
    "parse_nmap_xml", "detect_and_parse",
]

import xml.etree.ElementTree as ET


def detect_and_parse(raw_bytes, filename=""):
    """
    Sniff the file type and dispatch. Returns (source_label, findings_list).
    Raises ValueError if it can't recognise the format.
    """
    name = (filename or "").lower()
    text_head = raw_bytes[:4000].decode("utf-8", "ignore").lower()

    # CSV detection first (no XML declaration, has comma header)
    is_xml = text_head.lstrip().startswith("<?xml") or text_head.lstrip().startswith("<")

    if not is_xml:
        # CSV — distinguish Nessus vs OpenVAS by header columns
        header = text_head.splitlines()[0] if text_head.splitlines() else ""
        if "plugin id" in header or "plugin_id" in header or ("risk" in header and "host" in header):
            return "Nessus CSV", parse_nessus_csv(raw_bytes)
        if "nvt" in header or "oid" in header or "solution type" in header:
            return "OpenVAS CSV", parse_openvas_csv(raw_bytes)
        # fall back: try Nessus CSV layout
        return "CSV", parse_nessus_csv(raw_bytes)

    # XML — inspect the root/markers
    if ".nessus" in name or "<NessusClientData" in raw_bytes[:4000].decode("utf-8", "ignore"):
        return "Nessus (.nessus)", parse_nessus_xml(raw_bytes)
    head = raw_bytes[:4000].decode("utf-8", "ignore")
    if "<report" in head.lower() and ("openvas" in head.lower() or "greenbone" in head.lower() or "<gmp" in head.lower() or "qod" in head.lower()):
        return "OpenVAS/Greenbone (XML)", parse_openvas_xml(raw_bytes)
    if "<nmaprun" in head.lower():
        return "Nmap (XML)", parse_nmap_xml(raw_bytes)
    # Try to disambiguate by parsing the root tag
    try:
        root = ET.fromstring(raw_bytes)
        tag = root.tag.lower()
        if "nmaprun" in tag:
            return "Nmap (XML)", parse_nmap_xml(raw_bytes)
        if "nessusclientdata" in tag:
            return "Nessus (.nessus)", parse_nessus_xml(raw_bytes)
        if "report" in tag:
            return "OpenVAS/Greenbone (XML)", parse_openvas_xml(raw_bytes)
    except ET.ParseError:
        pass
    raise ValueError("Could not recognise this file as Nessus, OpenVAS or Nmap output.")
