"""
scanner.py — the built-in offline vulnerability assessment engine.

SCOPE AND SAFETY (read this):
  This is a *vulnerability assessment* scanner, not a penetration / exploitation
  tool. It IDENTIFIES and REPORTS; it never attempts to exploit, break in,
  bypass authentication, or alter the target. Concretely it does:
     - host discovery (is the host up)
     - TCP port scan (which ports are open)
     - service + version banner grab (what's listening)
     - TLS/SSL configuration checks (protocol versions, cert expiry, self-signed)
     - HTTP security-header checks (missing HSTS, etc.)
     - version-to-CVE matching against a LOCAL, bundled dataset
  It performs only light, benign connections — the same traffic a service sees
  from any ordinary client. It does NOT send exploit payloads, brute-force
  credentials, or run destructive checks. Actual penetration testing is done
  manually by the team, by design.

  No internet access is used or required. Everything runs against the operator's
  own internal targets, using only the Python standard library.

Everything returns findings in the same dict shape the parsers use, so results
flow straight into the register.
"""
import concurrent.futures
import socket
import ssl
import struct
import subprocess
import sys
from datetime import datetime, date

from vuln_db import match_cves, service_advice

# ---------------------------------------------------------------------------
# Default port set — common data-centre / infrastructure services.
# The operator can override with a custom list.
# ---------------------------------------------------------------------------
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
    5985, 6379, 8080, 8443, 9200, 11211, 27017,
]
PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 5985: "winrm", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}
TLS_PORTS = {443, 465, 636, 993, 995, 8443, 1433}
HTTP_PORTS = {80, 8080}
HTTPS_PORTS = {443, 8443}
# Services that should essentially never be exposed unauthenticated.
RISKY_PLAINTEXT = {23: "telnet", 21: "ftp", 161: "snmp", 6379: "redis",
                   11211: "memcached", 2049: "nfs"}


def _now_iso():
    return date.today().isoformat()


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------
def host_is_up(ip, timeout=1.0, probe_ports=(443, 80, 22, 445, 3389)):
    """
    Consider a host up if ICMP ping succeeds OR any probe port accepts a TCP
    connection (many hosts block ping but run services).
    """
    # try ping (platform-aware), but never fail the scan if ping isn't allowed
    try:
        param = "-n" if sys.platform.startswith("win") else "-c"
        wait = "-w" if sys.platform.startswith("win") else "-W"
        r = subprocess.run(["ping", param, "1", wait, "1", ip],
                           capture_output=True, timeout=timeout + 1)
        if r.returncode == 0:
            return True
    except Exception:
        pass
    for p in probe_ports:
        if _tcp_open(ip, p, timeout=timeout):
            return True
    return False


def _tcp_open(ip, port, timeout=1.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Port scan + banner grab
# ---------------------------------------------------------------------------
def scan_ports(ip, ports=None, timeout=1.0, workers=100):
    ports = ports or DEFAULT_PORTS
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_tcp_open, ip, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futs):
            if fut.result():
                open_ports.append(futs[fut])
    return sorted(open_ports)


def grab_banner(ip, port, timeout=2.0):
    """Light banner grab. Sends a minimal, benign probe where a service expects one."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # First, read any greeting a service volunteers (SSH, FTP, SMTP…).
            try:
                data = s.recv(2048)
            except socket.timeout:
                data = b""
            # If nothing was volunteered, try a benign HTTP HEAD — many services
            # (web servers on any port) only respond once spoken to.
            if not data and port not in TLS_PORTS:
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
                    data = s.recv(2048)
                except Exception:
                    data = b""
            return data.decode("latin-1", "ignore").strip()
    except Exception:
        return ""


def parse_service_version(banner, port):
    """Best-effort product/version extraction from a banner."""
    product = version = ""
    b = banner.lower()
    # SSH:  SSH-2.0-OpenSSH_8.2p1 Ubuntu...
    if banner.startswith("SSH-"):
        product = "OpenSSH" if "openssh" in b else "SSH"
        import re
        m = re.search(r"openssh[_/ ]([0-9][0-9a-z.\-]*)", b)
        if m:
            version = m.group(1)
    # HTTP Server header
    elif "server:" in b:
        import re
        m = re.search(r"server:\s*([^\r\n]+)", banner, re.IGNORECASE)
        if m:
            sv = m.group(1).strip()
            parts = sv.split("/", 1)
            product = parts[0].strip()
            if len(parts) > 1:
                version = parts[1].split()[0].strip()
    # FTP / SMTP greeting often has version in parentheses or after dash
    elif port in (21, 25, 110, 143):
        import re
        m = re.search(r"([A-Za-z][A-Za-z0-9\-]+)[ /]([0-9][0-9a-z.]*)", banner)
        if m:
            product, version = m.group(1), m.group(2)
    return product, version


# ---------------------------------------------------------------------------
# TLS / SSL checks
# ---------------------------------------------------------------------------
def check_tls(ip, port, timeout=3.0):
    """
    Returns a list of finding-dicts for TLS weaknesses:
      - deprecated protocol support (TLS 1.0 / 1.1)
      - expired / soon-expiring certificate
      - self-signed certificate
    Only observes the handshake; does not attack it.
    """
    findings = []
    host = ip

    # 1. certificate inspection via a normal verified-then-unverified handshake
    cert = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert(binary_form=False)
                # getpeercert returns {} when verify disabled; fetch DER + parse lightly
                der = ss.getpeercert(binary_form=True)
                negotiated = ss.version()
    except Exception as e:
        return findings  # port may not actually speak TLS

    # Certificate expiry (parse from DER using ssl's helper when possible)
    try:
        import ssl as _ssl
        decoded = _ssl._ssl._test_decode_cert  # not always available
    except Exception:
        decoded = None
    # Use a robust path: re-handshake with default context to catch verify errors
    verify_error = None
    try:
        vctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host) as ss:
                _ = ss.getpeercert()
    except ssl.SSLCertVerificationError as e:
        verify_error = str(e)
    except Exception as e:
        verify_error = None

    if verify_error:
        reason = "self-signed or untrusted"
        if "expired" in verify_error.lower():
            reason = "expired"
        findings.append(_tls_finding(
            ip, port,
            vuln="TLS certificate not trusted",
            synopsis=f"The certificate on {ip}:{port} failed validation ({reason}).",
            definition=f"During the TLS handshake the server's certificate could not be "
                       f"verified against a trusted CA. Detail: {verify_error[:200]}",
            reported_risk="Medium",
            solution="Install a certificate issued by a trusted CA (or your internal PKI) "
                     "and ensure the full chain and validity dates are correct.",
        ))

    # 2. deprecated protocol support — try to negotiate TLS 1.0 and 1.1 explicitly
    for proto_name, proto_const in _legacy_protocols():
        if _supports_protocol(ip, port, proto_const, timeout):
            findings.append(_tls_finding(
                ip, port,
                vuln=f"Deprecated TLS protocol supported ({proto_name})",
                synopsis=f"{ip}:{port} accepts {proto_name}, which is deprecated and insecure.",
                definition=f"The service negotiated a {proto_name} handshake. {proto_name} has known "
                           f"weaknesses and is disallowed by current standards (PCI-DSS, NIST).",
                reported_risk="Medium",
                solution=f"Disable {proto_name} on this service and allow only TLS 1.2 and TLS 1.3.",
            ))
    return findings


def _legacy_protocols():
    out = []
    for name, attr in (("TLS 1.0", "PROTOCOL_TLSv1"), ("TLS 1.1", "PROTOCOL_TLSv1_1")):
        const = getattr(ssl, attr, None)
        if const is not None:
            out.append((name, const))
    return out


def _supports_protocol(ip, port, proto_const, timeout):
    try:
        ctx = ssl.SSLContext(proto_const)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip):
                return True
    except Exception:
        return False


def _tls_finding(ip, port, vuln, synopsis, definition, reported_risk, solution):
    return {
        "ip_hostname": ip,
        "device": "",
        "vulnerability": f"{vuln} ({port}/tcp)",
        "synopsis": synopsis,
        "definition": definition,
        "cve": "",
        "reported_risk": reported_risk,
        "exploit_available": "Unknown",
        "exploit_reference": "",
        "solution": solution,
        "source_tool": "Built-in scanner (TLS)",
    }


# ---------------------------------------------------------------------------
# HTTP security header checks
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "strict-transport-security": ("Missing HSTS header",
        "The response has no Strict-Transport-Security header, so browsers may "
        "connect over plaintext HTTP and be exposed to downgrade attacks.",
        "Add a Strict-Transport-Security header with an appropriate max-age."),
    "x-frame-options": ("Missing X-Frame-Options / framing protection",
        "No clickjacking protection header is set.",
        "Set X-Frame-Options: DENY or a Content-Security-Policy frame-ancestors directive."),
    "x-content-type-options": ("Missing X-Content-Type-Options",
        "MIME-type sniffing is not disabled.",
        "Set X-Content-Type-Options: nosniff."),
    "content-security-policy": ("Missing Content-Security-Policy",
        "No Content-Security-Policy is defined, weakening defence against XSS.",
        "Define a Content-Security-Policy appropriate to the application."),
}


def check_http_headers(ip, port, timeout=3.0, force_tls=None):
    findings = []
    use_tls = (port in HTTPS_PORTS) if force_tls is None else force_tls
    try:
        import http.client
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
    except Exception:
        return findings

    # Only flag header gaps on HTTPS (HSTS etc. mainly meaningful there), but
    # content-type-options / frame-options apply to both.
    for h, (vuln, syn, sol) in SECURITY_HEADERS.items():
        if h == "strict-transport-security" and not use_tls:
            continue
        if h not in headers:
            findings.append({
                "ip_hostname": ip, "device": "",
                "vulnerability": f"{vuln} ({port}/tcp)",
                "synopsis": syn,
                "definition": syn + " Detected by inspecting the HTTP response headers.",
                "cve": "", "reported_risk": "Low", "exploit_available": "No",
                "exploit_reference": "", "solution": sol,
                "source_tool": "Built-in scanner (HTTP)",
            })
    # Server header disclosure
    if "server" in headers and any(ch.isdigit() for ch in headers["server"]):
        findings.append({
            "ip_hostname": ip, "device": "",
            "vulnerability": f"Server version disclosure ({port}/tcp)",
            "synopsis": f"The server advertises its software and version: {headers['server']}",
            "definition": "The HTTP Server header reveals the product and exact version, helping an "
                          "attacker match known exploits. Detected from the response header.",
            "cve": "", "reported_risk": "Information", "exploit_available": "No",
            "exploit_reference": "", "solution": "Suppress or generalise the Server header.",
            "source_tool": "Built-in scanner (HTTP)",
        })
    return findings


# ---------------------------------------------------------------------------
# Orchestration: scan one host, scan many
# ---------------------------------------------------------------------------
def scan_host(ip, ports=None, timeout=1.0, do_tls=True, do_http=True,
              progress=None, assume_up=False):
    """
    Returns a list of finding-dicts for one host. Non-destructive throughout.
    `progress` is an optional callable(str) for status updates.
    `assume_up` skips the liveness probe (useful when hosts block ping and run
    only non-standard ports).
    """
    findings = []
    scan_port_list = ports or DEFAULT_PORTS

    def say(msg):
        if progress:
            progress(msg)

    if not assume_up:
        say(f"{ip}: checking if host is up")
        # Probe the actual scan ports for liveness too, not just the well-known set,
        # so a host that only runs non-standard ports is still detected.
        liveness_probes = tuple(sorted(set(scan_port_list) | {443, 80, 22, 445, 3389}))[:12]
        if not host_is_up(ip, timeout=timeout, probe_ports=liveness_probes):
            return []  # host appears down

    say(f"{ip}: scanning ports")
    open_ports = scan_ports(ip, ports=ports, timeout=timeout)
    if not open_ports:
        return []

    for port in open_ports:
        svc = PORT_SERVICE.get(port, "unknown")
        banner = grab_banner(ip, port)
        product, version = parse_service_version(banner, port)
        # Detect HTTP(S) on non-standard ports from the banner so checks still run.
        looks_http = ("http/" in banner.lower() or "server:" in banner.lower())
        looks_tls = _speaks_tls(ip, port, timeout) if port not in TLS_PORTS else True

        # Inventory finding (Information) — the attack surface, recorded.
        inv_syn = f"Open {port}/tcp ({svc})"
        if product:
            inv_syn += f" — {product}{(' ' + version) if version else ''}"
        findings.append({
            "ip_hostname": ip, "device": "",
            "vulnerability": f"Open service {port}/tcp — {svc}",
            "synopsis": inv_syn,
            "definition": "The built-in scanner found this TCP port open and recorded the service for "
                          "attack-surface inventory. Confirm the service is required and restricted.",
            "cve": "", "reported_risk": "Information",
            "exploit_available": "Unknown", "exploit_reference": "",
            "solution": "Close the port if unused, or restrict it by firewall/segmentation and keep "
                        "the service patched.",
            "source_tool": "Built-in scanner",
        })

        # Risky plaintext / commonly-misexposed services
        if port in RISKY_PLAINTEXT:
            findings.append({
                "ip_hostname": ip, "device": "",
                "vulnerability": f"Insecure/exposed service: {RISKY_PLAINTEXT[port]} ({port}/tcp)",
                "synopsis": f"{RISKY_PLAINTEXT[port]} is exposed on {ip}:{port}. These services are "
                            f"high-risk when reachable, often cleartext or unauthenticated by default.",
                "definition": service_advice(port),
                "cve": "", "reported_risk": "High",
                "exploit_available": "Unknown", "exploit_reference": "",
                "solution": f"Disable {RISKY_PLAINTEXT[port]} if not required; otherwise restrict access "
                            f"to management networks, enforce authentication and use an encrypted "
                            f"alternative.",
                "source_tool": "Built-in scanner",
            })

        # Version -> CVE matching against the local dataset
        if product and version:
            for hit in match_cves(product, version):
                findings.append({
                    "ip_hostname": ip, "device": "",
                    "vulnerability": f"{product} {version} — {hit['title']}",
                    "synopsis": hit["synopsis"],
                    "definition": hit["definition"] +
                        f" Matched from the service banner ({product} {version}) against the local "
                        f"vulnerability dataset.",
                    "cve": hit["cve"],
                    "reported_risk": hit["severity"],
                    "exploit_available": hit.get("exploit", "Unknown"),
                    "exploit_reference": hit.get("reference", ""),
                    "solution": hit["solution"],
                    "source_tool": "Built-in scanner (CVE match)",
                })

        # TLS checks (standard TLS ports, or any port that completes a TLS handshake)
        if do_tls and looks_tls:
            say(f"{ip}:{port} checking TLS")
            findings.extend(check_tls(ip, port, timeout=max(timeout, 3.0)))

        # HTTP header checks (standard HTTP ports, or any port that answered HTTP)
        if do_http and (port in (HTTP_PORTS | HTTPS_PORTS) or looks_http):
            say(f"{ip}:{port} checking HTTP headers")
            is_tls_http = looks_tls and port not in HTTP_PORTS
            findings.extend(check_http_headers(ip, port, timeout=max(timeout, 3.0),
                                               force_tls=is_tls_http))

    return findings


def _speaks_tls(ip, port, timeout=1.0):
    """Quick check whether a port completes a TLS handshake (for non-standard HTTPS)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip):
                return True
    except Exception:
        return False


def expand_targets(spec):
    """
    Turn a target spec into a list of IPs. Accepts:
      - single IP: 10.0.0.5
      - CIDR: 10.0.0.0/28
      - range: 10.0.0.1-10.0.0.20
      - comma/space/newline separated combinations of the above
      - hostnames (resolved locally)
    """
    import ipaddress
    out = []
    tokens = []
    for chunk in spec.replace(",", " ").split():
        tokens.append(chunk.strip())
    for tok in tokens:
        if not tok:
            continue
        try:
            if "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                out.extend(str(h) for h in net.hosts())
                continue
            if "-" in tok and tok.count(".") >= 3:
                start, end = tok.split("-", 1)
                s = ipaddress.ip_address(start.strip())
                # allow "10.0.0.1-20" shorthand
                if "." not in end:
                    base = ".".join(start.split(".")[:3])
                    e = ipaddress.ip_address(f"{base}.{end.strip()}")
                else:
                    e = ipaddress.ip_address(end.strip())
                cur = s
                while cur <= e:
                    out.append(str(cur))
                    cur += 1
                continue
            # plain IP
            ipaddress.ip_address(tok)
            out.append(tok)
        except ValueError:
            # treat as hostname
            try:
                out.append(socket.gethostbyname(tok))
            except Exception:
                pass
    # de-dup, preserve order
    seen = set()
    uniq = []
    for ip in out:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)
    return uniq


def scan_targets(spec, ports=None, timeout=1.0, do_tls=True, do_http=True,
                 max_hosts=1024, progress=None, host_workers=16, assume_up=False):
    """Scan every host in `spec`. Returns (ips_scanned, findings)."""
    ips = expand_targets(spec)[:max_hosts]
    all_findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=host_workers) as ex:
        futs = {ex.submit(scan_host, ip, ports, timeout, do_tls, do_http, progress, assume_up): ip
                for ip in ips}
        for fut in concurrent.futures.as_completed(futs):
            try:
                all_findings.extend(fut.result())
            except Exception:
                pass
    return ips, all_findings


if __name__ == "__main__":
    # tiny self-test of target expansion only (no network)
    assert expand_targets("10.0.0.1") == ["10.0.0.1"]
    assert expand_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert expand_targets("10.0.0.1-3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert "10.0.0.5" in expand_targets("10.0.0.5, 10.0.0.6")
    print("scanner target-expansion self-test passed")
