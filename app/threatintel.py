"""
threatintel.py — offline-first threat-intelligence matching.

SECURITY MODEL (read this before changing anything):
  The asset inventory NEVER leaves this machine. The only network activity this
  module performs is *downloading public vulnerability feeds*. That is enforced
  structurally, not by convention:

    * The only function that touches the network is `fetch_url`, and it is
      FETCH-ONLY: it issues an HTTP GET with no request body, to a URL that must
      be a member of a caller-supplied allow-set, and it strips any attempt to
      attach data. There is no code path that POSTs, PUTs, or sends a body.
    * `fetch_source` can only be given a *source id*; the URL comes from the
      hardcoded SOURCES registry, never from the caller. There is no parameter
      through which asset data (IPs, hostnames, inventory) could be transmitted.
    * Matching (`match`) runs entirely locally on data already in the database,
      keyed on product and CVE — never on IP address.

  The allow-list below is the complete set of endpoints the app may contact.
  The Settings page exposes these as checkboxes; disabling one removes it from
  the set the app will fetch. Nothing outside this list is ever contacted.
"""
import gzip
import io
import json
import re
import urllib.request

# --- the complete allow-list of public feed sources -------------------------
SOURCES = [
    {
        "id": "cisa_kev",
        "name": "CISA Known Exploited Vulnerabilities (KEV)",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "kind": "kev",
        "desc": "Vulnerabilities CISA confirms are being actively exploited. Highest-priority signal.",
    },
    {
        "id": "nvd_recent",
        "name": "NVD — recently modified CVEs",
        "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz",
        "kind": "nvd",
        "desc": "Recently added or changed CVE records from the US National Vulnerability Database.",
    },
    {
        "id": "nvd_recent_new",
        "name": "NVD — recent new CVEs",
        "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
        "kind": "nvd",
        "desc": "The most recently published CVE records from the NVD.",
    },
]

SOURCE_BY_ID = {s["id"]: s for s in SOURCES}
_ALL_URLS = {s["url"] for s in SOURCES}

# fixed, non-identifying request header. Deliberately generic — carries nothing
# about this deployment or its assets.
_UA = "Argus-FeedSync/1.0 (+offline vulnerability feed update)"

# bounds on untrusted downloads (memory-exhaustion / zip-bomb guards)
MAX_DOWNLOAD = 80 * 1024 * 1024        # 80 MB compressed/raw
MAX_DECOMPRESSED = 400 * 1024 * 1024   # 400 MB after gunzip


class FetchError(Exception):
    pass


def fetch_url(url, allow, proxy=None, timeout=30):
    """
    FETCH-ONLY network primitive. GET `url`, but only if it is in `allow`.
    - Never sends a body (HTTP GET, data=None).
    - Sends only a fixed generic User-Agent; no asset-derived headers.
    - `proxy` optionally routes through the org's egress proxy.
    Returns raw bytes. Raises FetchError on any disallowed URL or failure.
    """
    if url not in allow:
        raise FetchError(f"Refused: {url!r} is not in the allow-list.")
    # Request with explicit GET and no data. There is no parameter that could
    # carry request content, and we assert it below as defence in depth.
    req = urllib.request.Request(url, data=None, method="GET")
    req.add_header("User-Agent", _UA)
    req.add_header("Accept", "application/json, application/gzip, */*")
    if req.data is not None:          # must never happen
        raise FetchError("Refused: request body present on a fetch-only call.")
    if proxy:
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        opener = urllib.request.build_opener(handler)
    else:
        opener = urllib.request.build_opener()
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_DOWNLOAD + 1)   # bounded read
    except Exception as e:
        raise FetchError(f"Could not fetch {url}: {e}")
    if len(raw) > MAX_DOWNLOAD:
        raise FetchError(f"Refused: {url} response exceeds {MAX_DOWNLOAD} bytes.")
    # transparently gunzip, with a bound on the decompressed size (zip-bomb guard)
    if url.endswith(".gz") or raw[:2] == b"\x1f\x8b":
        try:
            dec = gzip.GzipFile(fileobj=io.BytesIO(raw))
            out = dec.read(MAX_DECOMPRESSED + 1)
            if len(out) > MAX_DECOMPRESSED:
                raise FetchError(f"Refused: {url} decompresses to over {MAX_DECOMPRESSED} bytes.")
            raw = out
        except FetchError:
            raise
        except Exception:
            pass
    return raw


def fetch_source(source_id, proxy=None, timeout=30):
    """Fetch one allow-listed source by id. URL comes from SOURCES, not the caller."""
    src = SOURCE_BY_ID.get(source_id)
    if not src:
        raise FetchError(f"Unknown source id: {source_id!r}")
    raw = fetch_url(src["url"], _ALL_URLS, proxy=proxy, timeout=timeout)
    return parse_feed(src, raw)


# --- parsers ---------------------------------------------------------------
def parse_feed(src, raw):
    kind = src["kind"]
    if kind == "kev":
        return parse_kev(raw, src["name"])
    if kind == "nvd":
        return parse_nvd(raw, src["name"])
    return []


def parse_kev(raw, source_name="CISA KEV"):
    recs = []
    try:
        data = json.loads(raw.decode("utf-8", "ignore"))
    except Exception:
        return recs
    for v in data.get("vulnerabilities", []):
        recs.append({
            "cve": (v.get("cveID") or "").upper(),
            "title": v.get("vulnerabilityName") or "",
            "products": [p for p in [v.get("product"), v.get("vendorProject")] if p],
            "severity": "Critical",     # KEV = actively exploited → treat as top priority
            "source": source_name, "kev": True,
            "date": v.get("dateAdded") or "",
            "summary": v.get("shortDescription") or "",
        })
    return recs


def parse_nvd(raw, source_name="NVD"):
    recs = []
    try:
        data = json.loads(raw.decode("utf-8", "ignore"))
    except Exception:
        return recs
    items = data.get("CVE_Items") or data.get("vulnerabilities") or []
    for it in items:
        cve_obj = it.get("cve", it)
        cid = (cve_obj.get("CVE_data_meta", {}).get("ID")
               or cve_obj.get("id") or "").upper()
        if not cid:
            continue
        # description
        desc = ""
        dd = (cve_obj.get("description", {}) or {}).get("description_data") \
            or cve_obj.get("descriptions") or []
        if dd:
            desc = dd[0].get("value", "")
        # severity from CVSS v3 if present
        sev = ""
        impact = it.get("impact", {}) or {}
        base = (impact.get("baseMetricV3", {}) or {}).get("cvssV3", {})
        if base:
            sev = (base.get("baseSeverity") or "").title()
        # affected products from CPE nodes
        products = set()
        for node in _walk_nodes(it.get("configurations", {})):
            for cpe in node.get("cpe_match", []) or []:
                uri = cpe.get("cpe23Uri", "")
                parts = uri.split(":")
                if len(parts) > 4 and parts[4] and parts[4] != "*":
                    products.add(parts[4].replace("_", " "))
        recs.append({
            "cve": cid, "title": desc[:120], "products": sorted(products),
            "severity": sev or "Medium", "source": source_name, "kev": False,
            "date": cve_obj.get("published") or "", "summary": desc,
        })
    return recs


def _walk_nodes(configurations):
    nodes = []
    if isinstance(configurations, dict):
        nodes = configurations.get("nodes", []) or []
    out = []
    stack = list(nodes)
    while stack:
        n = stack.pop()
        out.append(n)
        stack.extend(n.get("children", []) or [])
    return out


# --- local matching (no IPs involved) --------------------------------------
_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Information": 0, "": 0}


def match(feed_records, findings, assets):
    """
    Match feed records against local data. Returns a list of alerts.
    Keyed on CVE and product text — never on IP. Each alert references the
    affected findings/assets by their internal records for action, but that
    linkage stays entirely local.
    """
    # index local CVEs and product-ish text
    cve_to_findings = {}
    for f in findings:
        cve = (f.get("cve") or "").upper().strip()
        if cve:
            cve_to_findings.setdefault(cve, []).append(f)
    # product text corpus from findings + asset descriptions
    corpus = []
    for f in findings:
        corpus.append((("%s %s" % (f.get("vulnerability", ""), f.get("synopsis", ""))).lower(), "finding", f))
    for a in assets:
        corpus.append((("%s %s" % (a.get("hostname", ""), a.get("description", ""))).lower(), "asset", a))

    alerts = []
    seen = set()
    for rec in feed_records:
        cve = rec["cve"]
        matched_findings, matched_assets, reason = [], [], ""
        # 1) CVE cross-reference against existing findings (strongest signal)
        if cve and cve in cve_to_findings:
            matched_findings = cve_to_findings[cve]
            reason = ("Actively exploited (in CISA KEV) and present in your findings"
                      if rec["kev"] else "Listed in the feed and present in your findings")
        # 2) product match (only if we have product names to match on)
        if not matched_findings and rec["products"]:
            for prod in rec["products"]:
                p = str(prod).lower().strip()
                if len(p) < 3:
                    continue
                for text, kind, obj in corpus:
                    if re.search(r"\b" + re.escape(p) + r"\b", text):
                        if kind == "finding":
                            matched_findings.append(obj)
                        else:
                            matched_assets.append(obj)
                if matched_findings or matched_assets:
                    reason = (f"Affects {prod}, which appears in your "
                              + ("findings" if matched_findings else "asset inventory")
                              + (" (actively exploited — CISA KEV)" if rec["kev"] else ""))
                    break
        if not (matched_findings or matched_assets):
            continue
        key = (cve, reason)
        if key in seen:
            continue
        seen.add(key)
        alerts.append({
            "cve": cve, "title": rec["title"], "severity": rec["severity"],
            "source": rec["source"], "kev": rec["kev"], "reason": reason,
            "date": rec.get("date", ""), "summary": rec.get("summary", ""),
            "finding_ids": [f.get("id") for f in matched_findings if f.get("id")],
            "asset_hosts": sorted({a.get("hostname") or a.get("ip") for a in matched_assets}),
            "hosts": sorted({f.get("ip_hostname") for f in matched_findings if f.get("ip_hostname")}),
        })
    alerts.sort(key=lambda a: (not a["kev"], -_SEV_RANK.get(a["severity"], 0), a["cve"]))
    return alerts


# --- self-tests ------------------------------------------------------------
if __name__ == "__main__":
    import threading, http.server

    # 1) fetch-only guard: a non-allowlisted URL is refused
    try:
        fetch_url("https://evil.example/x", {"https://good.example/y"})
        raise SystemExit("FAIL: disallowed URL was not refused")
    except FetchError:
        pass

    # 2) the network primitive issues GET with no body
    seen = {}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            seen["method"] = self.command
            seen["len"] = self.headers.get("Content-Length")
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"vulnerabilities":[]}')
        def do_POST(self):
            seen["method"] = "POST"
            self.send_response(200); self.end_headers()

    srv = http.server.HTTPServer(("127.0.0.1", 8921), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:8921/feed.json"
    body = fetch_url(url, {url})
    assert seen["method"] == "GET", seen
    assert seen["len"] in (None, "0"), seen       # no request body
    srv.shutdown()

    # 3) KEV parse + match by CVE
    kev = parse_kev(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2019-0708", "vulnerabilityName": "BlueKeep",
         "product": "Remote Desktop", "vendorProject": "Microsoft",
         "dateAdded": "2022-01-01", "shortDescription": "RCE"}]}).encode())
    assert kev[0]["kev"] and kev[0]["cve"] == "CVE-2019-0708"
    findings = [{"id": 5, "cve": "CVE-2019-0708", "vulnerability": "BlueKeep RDP",
                 "synopsis": "", "ip_hostname": "10.0.0.9"}]
    alerts = match(kev, findings, [])
    assert alerts and alerts[0]["cve"] == "CVE-2019-0708" and alerts[0]["kev"], alerts
    assert 5 in alerts[0]["finding_ids"]

    # 4) product match against asset inventory
    recs = [{"cve": "CVE-2021-1", "title": "openssl flaw", "products": ["openssl"],
             "severity": "High", "source": "NVD", "kev": False, "date": ""}]
    a = match(recs, [], [{"hostname": "web1", "description": "runs OpenSSL 1.0.2", "ip": "10.0.0.1"}])
    assert a and a[0]["cve"] == "CVE-2021-1", a

    print("threatintel self-tests passed")
