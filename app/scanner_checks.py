"""
scanner_checks.py — additional assessment modules for the built-in scanner.

SCOPE AND SAFETY (same contract as scanner.py):
  Every check here is *detection only*. It reads what a service voluntarily
  advertises during the ordinary, pre-authentication part of its protocol — the
  same information any client sees — and never authenticates, sends exploit
  payloads, brute-forces, or alters the target. Specifically:

    - TLS: inspects the negotiated cipher and the certificate's own validity
      dates (no attack on the handshake).
    - SSH: reads the server's KEXINIT, i.e. the list of algorithms it offers,
      exactly like ssh-audit. No key exchange is completed, no login attempted.
    - SMB: sends only a NEGOTIATE request (the first, pre-auth packet) and reads
      the signing flag and dialect. No tree connect, no session setup.
    - RDP: sends only the X.224 negotiation request and reads which security
      layer the server requires. No channel is established, no credentials sent.
    - HTTP: sends OPTIONS/GET and inspects the Allow header, Set-Cookie flags and
      whether a directory listing is returned.

  Each function is wrapped so any protocol/parse hiccup yields no finding rather
  than crashing a scan. Standard library only; works fully offline.

Findings use the same dict shape as scanner.py / the parsers.
"""
import re
import socket
import ssl
import struct

SRC_TLS = "Built-in scanner (TLS)"
SRC_SSH = "Built-in scanner (SSH)"
SRC_SMB = "Built-in scanner (SMB)"
SRC_RDP = "Built-in scanner (RDP)"
SRC_HTTP = "Built-in scanner (HTTP)"
SRC_SVC = "Built-in scanner"


def _finding(ip, port, vuln, synopsis, definition, risk, solution, source,
             cve="", exploit="Unknown", ref=""):
    return {
        "ip_hostname": ip, "device": "",
        "vulnerability": f"{vuln} ({port}/tcp)" if port else vuln,
        "synopsis": synopsis, "definition": definition,
        "cve": cve, "reported_risk": risk,
        "exploit_available": exploit, "exploit_reference": ref,
        "solution": solution, "source_tool": source,
    }


# ===========================================================================
# TLS — certificate validity window + weak negotiated cipher
# ===========================================================================
WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES-", "DES_", "NULL", "EXPORT", "MD5",
                      "ANON", "ADH", "AECDH", "IDEA", "SEED", "CAMELLIA128-")


def check_tls_quality(ip, port, timeout=3.0):
    """Negotiated-cipher strength, forward secrecy and certificate validity window."""
    findings = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")  # observe weak ciphers if the server offers them
        except ssl.SSLError:
            pass
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ss:
                cipher = ss.cipher()            # (name, protocol, secret_bits)
                der = ss.getpeercert(binary_form=True)
    except Exception:
        return findings

    # --- cipher strength / forward secrecy ---
    if cipher:
        name, proto, bits = (cipher + (None, None, None))[:3]
        up = (name or "").upper()
        if any(tok in up for tok in WEAK_CIPHER_TOKENS):
            findings.append(_finding(
                ip, port, "Weak TLS cipher suite negotiated",
                f"{ip}:{port} negotiated {name}, a weak/legacy cipher.",
                f"The server agreed to the cipher suite {name} ({bits}-bit). Suites using RC4, "
                "3DES, DES, EXPORT, NULL or MD5 are considered broken or weak and are disallowed "
                "by PCI-DSS and NIST.",
                "Medium",
                "Restrict the cipher list to modern AEAD suites (AES-GCM / ChaCha20-Poly1305) "
                "with ECDHE key exchange; disable RC4, 3DES, DES, EXPORT and NULL ciphers.",
                SRC_TLS))
        elif isinstance(bits, int) and bits and bits < 128:
            findings.append(_finding(
                ip, port, "Weak TLS encryption strength",
                f"{ip}:{port} negotiated only {bits}-bit encryption ({name}).",
                f"The negotiated cipher {name} provides {bits}-bit symmetric strength, below the "
                "112/128-bit minimum expected today.",
                "Medium",
                "Disable ciphers below 128-bit and prefer AES-128-GCM or stronger.",
                SRC_TLS))
        elif up and ("ECDHE" not in up and "DHE" not in up):
            findings.append(_finding(
                ip, port, "TLS cipher without forward secrecy",
                f"{ip}:{port} negotiated {name}, which does not provide forward secrecy.",
                f"The negotiated cipher {name} uses static key exchange. Without (EC)DHE, capture "
                "of the server key later exposes all previously recorded sessions.",
                "Low",
                "Prefer ECDHE/DHE key-exchange cipher suites so each session has an ephemeral key.",
                SRC_TLS))

    # --- certificate validity window (the cert's own notBefore/notAfter) ---
    info = _decode_cert(der)
    if info:
        from datetime import datetime
        na = info.get("notAfter")
        nb = info.get("notBefore")
        now = datetime.utcnow()
        exp = _parse_cert_time(na)
        start = _parse_cert_time(nb)
        if exp:
            days = (exp - now).days
            if days < 0:
                findings.append(_finding(
                    ip, port, "Expired TLS certificate",
                    f"The certificate on {ip}:{port} expired {abs(days)} day(s) ago ({na}).",
                    "The presented X.509 certificate is past its notAfter date, so clients will warn "
                    "or refuse to connect and the identity is unverifiable.",
                    "High",
                    "Renew the certificate immediately and automate renewal to prevent recurrence.",
                    SRC_TLS))
            elif days <= 30:
                findings.append(_finding(
                    ip, port, "TLS certificate expiring soon",
                    f"The certificate on {ip}:{port} expires in {days} day(s) ({na}).",
                    "The certificate is within 30 days of expiry. An expired certificate causes an "
                    "outage and client trust errors.",
                    "Medium",
                    "Renew ahead of expiry and put automated renewal/monitoring in place.",
                    SRC_TLS))
        if start and start > now:
            findings.append(_finding(
                ip, port, "TLS certificate not yet valid",
                f"The certificate on {ip}:{port} is not valid until {nb}.",
                "The certificate's notBefore date is in the future, often a sign of a clock or "
                "issuance error; clients will reject it.",
                "Medium",
                "Check the server clock and reissue the certificate with correct validity dates.",
                SRC_TLS))
        # self-signed by its own subject == issuer (corroborates the verify check)
        subj = info.get("subject")
        iss = info.get("issuer")
        if subj and iss and subj == iss:
            findings.append(_finding(
                ip, port, "Self-signed TLS certificate",
                f"The certificate on {ip}:{port} is self-signed (subject equals issuer).",
                "The certificate is its own issuer, so it chains to no trusted CA and provides no "
                "third-party identity assurance.",
                "Low",
                "Replace with a certificate from a trusted public CA or your internal PKI.",
                SRC_TLS))
    return findings


def _decode_cert(der):
    """Decode a DER cert to the dict ssl normally returns, via the stdlib helper."""
    if not der:
        return None
    try:
        import tempfile, os
        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(pem)
            return ssl._ssl._test_decode_cert(path)  # stdlib, parses to dict
        finally:
            os.remove(path)
    except Exception:
        return None


def _parse_cert_time(s):
    if not s:
        return None
    from datetime import datetime
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    return None


# ===========================================================================
# SSH — read the server's advertised algorithms (KEXINIT), like ssh-audit
# ===========================================================================
WEAK_SSH = {
    "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1", "rsa1024-sha1", "gss-group1-sha1"],
    "key": ["ssh-rsa", "ssh-dss", "rsa-sha2-256-cert", "ssh-rsa-cert-v01@openssh.com"],
    "enc": ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc",
            "cast128-cbc", "arcfour", "arcfour128", "arcfour256", "des-cbc", "none"],
    "mac": ["hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
            "umac-64@openssh.com", "hmac-ripemd160", "none"],
}


def check_ssh(ip, port, timeout=4.0, banner=None):
    findings = []
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            ident = _recv_line(s)
            if not ident.startswith("SSH-"):
                return findings
            s.sendall(b"SSH-2.0-VAPTScanner_assessment\r\n")
            payload = _read_ssh_packet_payload(s)
    except Exception:
        return findings

    # outdated OpenSSH from the banner
    m = re.search(r"openssh[_/ ]([0-9]+)\.([0-9]+)", ident, re.I)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        if (major, minor) < (7, 4):
            findings.append(_finding(
                ip, port, "Outdated OpenSSH version",
                f"{ip}:{port} runs OpenSSH {major}.{minor} ({ident.strip()}).",
                f"The SSH banner reports OpenSSH {major}.{minor}, a release with multiple fixed "
                "security issues in later versions.",
                "Medium",
                "Upgrade OpenSSH to a current, supported release.",
                SRC_SSH))

    if not payload or payload[0] != 20:  # 20 == SSH_MSG_KEXINIT
        return findings
    lists = _parse_kexinit(payload)
    if not lists:
        return findings
    names = ["kex", "key", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c"]
    offered = {}
    for i, key in enumerate(names):
        offered[key] = lists[i] if i < len(lists) else []

    weak_found = []
    for algo in offered.get("kex", []):
        if algo in WEAK_SSH["kex"]:
            weak_found.append(("key exchange", algo))
    for algo in offered.get("key", []):
        if algo in WEAK_SSH["key"]:
            weak_found.append(("host key", algo))
    for side in ("enc_c2s", "enc_s2c"):
        for algo in offered.get(side, []):
            if algo in WEAK_SSH["enc"] and ("cipher", algo) not in weak_found:
                weak_found.append(("cipher", algo))
    for side in ("mac_c2s", "mac_s2c"):
        for algo in offered.get(side, []):
            if algo in WEAK_SSH["mac"] and ("MAC", algo) not in weak_found:
                weak_found.append(("MAC", algo))

    # de-dup while keeping order
    seen, uniq = set(), []
    for kind, algo in weak_found:
        if (kind, algo) not in seen:
            seen.add((kind, algo)); uniq.append((kind, algo))
    if uniq:
        listing = ", ".join(f"{a} ({k})" for k, a in uniq[:12])
        findings.append(_finding(
            ip, port, "Weak SSH algorithms offered",
            f"{ip}:{port} offers weak SSH algorithms: {listing}.",
            "The server's SSH KEXINIT advertises algorithms considered weak or deprecated "
            "(SHA-1 key exchange/host keys, CBC ciphers, MD5/SHA-1 or 64-bit MACs, arcfour). "
            "Read from the server's advertised algorithm list only.",
            "Medium",
            "Restrict the server to strong algorithms: curve25519-sha256 / ecdh-sha2-nistp256+ "
            "key exchange, ed25519 / rsa-sha2-512 host keys, AES-GCM or ChaCha20 ciphers, and "
            "ETM SHA-2 MACs. Remove CBC ciphers, arcfour, and MD5/SHA-1/64-bit MACs.",
            SRC_SSH))
    return findings


def _recv_line(s, limit=512):
    buf = b""
    while b"\n" not in buf and len(buf) < limit:
        chunk = s.recv(1)
        if not chunk:
            break
        buf += chunk
    return buf.decode("latin-1", "ignore")


def _read_ssh_packet_payload(s, limit=35000):
    """Read one SSH binary packet and return its payload bytes (unencrypted KEXINIT)."""
    hdr = _recv_exact(s, 4)
    if len(hdr) < 4:
        return b""
    plen = struct.unpack(">I", hdr)[0]
    if plen <= 0 or plen > limit:
        return b""
    body = _recv_exact(s, plen)
    if len(body) < plen:
        return b""
    pad = body[0]
    return body[1:len(body) - pad]


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _parse_kexinit(payload):
    """payload: byte 0 = msgtype(20), 16-byte cookie, then 10 name-lists."""
    try:
        p = 1 + 16  # skip type + cookie
        lists = []
        for _ in range(10):
            if p + 4 > len(payload):
                break
            ln = struct.unpack(">I", payload[p:p + 4])[0]
            p += 4
            raw = payload[p:p + ln].decode("latin-1", "ignore")
            p += ln
            lists.append([a for a in raw.split(",") if a])
        return lists
    except Exception:
        return None


# ===========================================================================
# SMB — NEGOTIATE only: read signing requirement and whether SMBv1 answers
# ===========================================================================
def check_smb(ip, port=445, timeout=4.0):
    findings = []
    # --- SMB2 negotiate: read SecurityMode (signing enabled/required) ---
    try:
        sm = _smb2_negotiate_securitymode(ip, port, timeout)
        if sm is not None:
            signing_required = bool(sm & 0x0002)
            if not signing_required:
                findings.append(_finding(
                    ip, port, "SMB signing not required",
                    f"{ip}:{port} does not require SMB signing.",
                    "The SMB2 NEGOTIATE response advertises SecurityMode without "
                    "SIGNING_REQUIRED, so sessions can proceed unsigned and are open to "
                    "relay / man-in-the-middle tampering. Read from the pre-auth negotiate only.",
                    "Medium",
                    "Require SMB signing on servers (and domain controllers via GPO: 'Microsoft "
                    "network server: Digitally sign communications (always)').",
                    SRC_SMB))
    except Exception:
        pass
    # --- SMBv1 detection: does the host answer an SMB1 negotiate? ---
    try:
        if _smb1_supported(ip, port, timeout):
            findings.append(_finding(
                ip, port, "SMBv1 protocol enabled",
                f"{ip}:{port} responds to the legacy SMBv1 protocol.",
                "The host answered an SMBv1 NEGOTIATE. SMBv1 is obsolete and associated with "
                "serious wormable vulnerabilities (e.g. MS17-010 / EternalBlue).",
                "High",
                "Disable SMBv1 entirely and use SMB2/3 only. On Windows, remove the SMB1 feature.",
                SRC_SMB, cve="CVE-2017-0144", exploit="Yes"))
    except Exception:
        pass
    return findings


def _smb2_negotiate_securitymode(ip, port, timeout):
    dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
    smb2 = b"\xfeSMB" + struct.pack("<H", 64) + b"\x00" * 2  # proto, structsize, creditcharge
    smb2 += b"\x00" * 4            # status
    smb2 += struct.pack("<H", 0)   # command NEGOTIATE (0)
    smb2 += struct.pack("<H", 0)   # credit req
    smb2 += b"\x00" * 4            # flags
    smb2 += b"\x00" * 4            # next command
    smb2 += b"\x00" * 8            # message id
    smb2 += b"\x00" * 4            # reserved/process id
    smb2 += b"\x00" * 4            # tree id
    smb2 += b"\x00" * 8            # session id
    smb2 += b"\x00" * 16           # signature
    body = struct.pack("<H", 36)                       # structure size
    body += struct.pack("<H", len(dialects))           # dialect count
    body += struct.pack("<H", 0x0001)                  # security mode: signing enabled
    body += struct.pack("<H", 0)                       # reserved
    body += struct.pack("<I", 0)                       # capabilities
    body += b"\x00" * 16                               # client guid
    body += b"\x00" * 8                                # client start time
    body += b"".join(struct.pack("<H", d) for d in dialects)
    msg = smb2 + body
    packet = struct.pack(">I", len(msg)) + msg          # direct-TCP 4-byte length
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(packet)
        resp = _recv_exact(s, 4)
        if len(resp) < 4:
            return None
        rlen = struct.unpack(">I", resp)[0]
        data = _recv_exact(s, min(rlen, 2048))
    if len(data) < 72 or data[:4] != b"\xfeSMB":
        return None
    # SMB2 header is 64 bytes; negotiate response: structsize(2), securitymode(2)...
    return struct.unpack("<H", data[64 + 2:64 + 4])[0]


def _smb1_supported(ip, port, timeout):
    # Minimal SMB1 NEGOTIATE offering common dialects.
    dialects = b"\x02NT LM 0.12\x00"
    params = b""  # wordcount 0
    smb1 = b"\xffSMB" + b"\x72"              # header + SMB_COM_NEGOTIATE
    smb1 += b"\x00" * 4                       # status
    smb1 += b"\x18"                           # flags
    smb1 += b"\x01\x28"                       # flags2
    smb1 += b"\x00" * 12                      # pid high + signature
    smb1 += b"\x00\x00"                       # reserved
    smb1 += b"\x00\x00"                       # tid
    smb1 += b"\x2f\x4b"                       # pid
    smb1 += b"\x00\x00"                       # uid
    smb1 += b"\x00\x00"                       # mid
    smb1 += b"\x00"                           # word count
    bcc = struct.pack("<H", len(dialects))
    msg = smb1 + bcc + dialects
    packet = struct.pack(">I", len(msg)) + msg
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(packet)
            resp = _recv_exact(s, 4)
            if len(resp) < 4:
                return False
            rlen = struct.unpack(">I", resp)[0]
            data = _recv_exact(s, min(rlen, 1024))
    except Exception:
        return False
    # An SMB1 reply keeps the \xffSMB signature; an SMB2-only host replies \xfeSMB.
    return len(data) >= 4 and data[:4] == b"\xffSMB"


# ===========================================================================
# RDP — X.224 negotiation only: which security layer does the server require?
# ===========================================================================
def check_rdp(ip, port=3389, timeout=4.0):
    findings = []
    try:
        sel, failure = _rdp_negotiate(ip, port, timeout)
    except Exception:
        return findings
    if sel is None and failure is None:
        return findings
    # failure codes: 1 SSL_REQUIRED, 5 HYBRID_REQUIRED (NLA). These mean good posture.
    if failure in (1, 5):
        return findings
    # A successful negotiation response to a plain-RDP request, or selected proto 0,
    # means standard RDP security is accepted -> NLA not enforced.
    if failure is None and (sel is None or sel == 0):
        findings.append(_finding(
            ip, port, "RDP Network Level Authentication not enforced",
            f"{ip}:{port} accepts standard RDP security (NLA/CredSSP not required).",
            "The server answered an X.224 negotiation offering only standard RDP security, so a "
            "client can connect without Network Level Authentication. This exposes the logon "
            "surface pre-authentication and allows man-in-the-middle on weak configurations. "
            "Read from the pre-auth negotiation only.",
            "Medium",
            "Require Network Level Authentication (CredSSP) and TLS on the RD Gateway / host; "
            "disable the legacy 'RDP Security Layer'.",
            SRC_RDP))
    return findings


def _rdp_negotiate(ip, port, timeout):
    # X.224 Connection Request with an RDP Negotiation Request offering PROTOCOL_RDP (0).
    neg_req = struct.pack("<BBHI", 0x01, 0x00, 0x08, 0x00000000)  # type, flags, len, requestedProtocols
    x224 = b"\x0e\xe0\x00\x00\x00\x00\x00"  # len, CR cdt, dst-ref, src-ref, class
    cookie = b"Cookie: mstshash=\r\n"
    user_data = cookie + neg_req
    tpkt_len = 4 + len(x224) + len(user_data)
    # fix X.224 length byte (length of the X.224 data that follows the length byte)
    x224 = struct.pack("B", len(x224) - 1 + len(user_data)) + x224[1:]
    tpkt = struct.pack(">BBH", 0x03, 0x00, tpkt_len)
    packet = tpkt + x224 + user_data
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(packet)
        data = _recv_exact(s, 19)
    if len(data) < 11 or data[0] != 0x03:
        return None, None
    # Look for an RDP Negotiation Response (type 0x02) or Failure (type 0x03) in the tail.
    tail = data[11:]
    if len(tail) >= 8:
        ntype = tail[0]
        if ntype == 0x02:   # NEG_RSP: selectedProtocol at offset 4 (uint32)
            sel = struct.unpack("<I", tail[4:8])[0]
            return sel, None
        if ntype == 0x03:   # NEG_FAILURE: failureCode at offset 4 (uint32)
            fail = struct.unpack("<I", tail[4:8])[0]
            return None, fail
    return None, None


# ===========================================================================
# HTTP — risky methods, cookie flags, directory listing
# ===========================================================================
def check_http_hardening(ip, port, use_tls, timeout=3.0):
    import http.client
    findings = []

    def _conn():
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        return http.client.HTTPConnection(ip, port, timeout=timeout)

    # --- risky methods via OPTIONS (benign) ---
    try:
        c = _conn(); c.request("OPTIONS", "/")
        r = c.getresponse(); allow = r.getheader("Allow", "") or ""; c.close()
        risky = [m for m in ("TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH")
                 if m in allow.upper()]
        if "TRACE" in allow.upper() or "TRACK" in allow.upper():
            findings.append(_finding(
                ip, port, "HTTP TRACE/TRACK method enabled",
                f"{ip}:{port} advertises the TRACE/TRACK method (Allow: {allow}).",
                "The server permits TRACE/TRACK, which can aid Cross-Site Tracing and header "
                "reflection. Detected from the OPTIONS Allow header.",
                "Low", "Disable the TRACE and TRACK methods on the web server.",
                SRC_HTTP))
        writey = [m for m in ("PUT", "DELETE", "PATCH") if m in allow.upper()]
        if writey:
            findings.append(_finding(
                ip, port, "Potentially unsafe HTTP methods enabled",
                f"{ip}:{port} advertises {', '.join(writey)} (Allow: {allow}).",
                "Write-capable HTTP methods are advertised. If not required and not strictly "
                "access-controlled, they broaden the attack surface. Detected from OPTIONS only; "
                "not exercised.",
                "Low", "Disable write methods unless required, and enforce authentication/ACLs.",
                SRC_HTTP))
    except Exception:
        pass

    # --- cookie flags + directory listing via a single GET ---
    try:
        c = _conn(); c.request("GET", "/")
        r = c.getresponse()
        set_cookie = r.getheader("Set-Cookie", "") or ""
        body = r.read(2048).decode("latin-1", "ignore")
        c.close()
        if set_cookie:
            low = set_cookie.lower()
            missing = []
            if "httponly" not in low:
                missing.append("HttpOnly")
            if use_tls and "secure" not in low:
                missing.append("Secure")
            if "samesite" not in low:
                missing.append("SameSite")
            if missing:
                findings.append(_finding(
                    ip, port, "Cookie set without hardening flags",
                    f"{ip}:{port} sets a cookie missing {', '.join(missing)}.",
                    "A Set-Cookie header lacks protective attributes "
                    f"({', '.join(missing)}), weakening session protection against theft or CSRF.",
                    "Low",
                    "Set HttpOnly, Secure (on HTTPS) and SameSite on session cookies.",
                    SRC_HTTP))
        if re.search(r"<title>\s*Index of /", body, re.I) or "Directory listing for" in body:
            findings.append(_finding(
                ip, port, "Directory listing enabled",
                f"{ip}:{port} returns an automatic directory index.",
                "The server returned a directory listing, exposing file names and structure that "
                "can reveal sensitive files. Detected from the response body of GET /.",
                "Low", "Disable automatic directory indexing (e.g. Options -Indexes).",
                SRC_HTTP))
    except Exception:
        pass
    return findings


# ===========================================================================
# Exposed data services — open, reachable data stores on the segment
# ===========================================================================
EXPOSED_SERVICES = {
    9200: ("Elasticsearch", "High", "Elasticsearch is reachable. If unauthenticated it exposes "
           "indexed data and cluster control."),
    27017: ("MongoDB", "High", "MongoDB is reachable. Historically a frequent source of data "
            "exposure when bound to untrusted networks."),
    6379: ("Redis", "High", "Redis is reachable. Redis is unauthenticated by default and can lead "
           "to data exposure or host compromise when exposed."),
    11211: ("Memcached", "High", "Memcached is reachable. It is unauthenticated and usable for "
            "data exposure and UDP amplification."),
    5432: ("PostgreSQL", "Medium", "A PostgreSQL port is reachable on this segment."),
    3306: ("MySQL/MariaDB", "Medium", "A MySQL/MariaDB port is reachable on this segment."),
    1433: ("Microsoft SQL Server", "Medium", "An MSSQL port is reachable on this segment."),
    1521: ("Oracle DB", "Medium", "An Oracle TNS listener is reachable on this segment."),
    5984: ("CouchDB", "High", "CouchDB is reachable on this segment."),
}


def exposed_service_finding(ip, port):
    """Return a finding dict if `port` is a sensitive data service, else None.
    Detection is by reachability only — no query or authentication is attempted."""
    if port not in EXPOSED_SERVICES:
        return None
    name, risk, why = EXPOSED_SERVICES[port]
    return _finding(
        ip, port, f"Exposed data service: {name}",
        f"{name} is reachable on {ip}:{port}.",
        why + " Flagged by reachability from the scanning host; authentication was not tested. "
        "Verify the service is firewalled to authorised hosts and requires authentication.",
        risk,
        f"Restrict {name} to the minimum necessary hosts via firewall/segmentation, require "
        "authentication, and bind it to internal interfaces only.",
        SRC_SVC)


# --------------------------------------------------------------------------
if __name__ == "__main__":
    # offline self-tests of the parsing helpers (no network)
    assert _parse_cert_time("Jan  1 00:00:00 2030 GMT") is not None
    # KEXINIT parse: type(20) + 16 cookie + one name-list "a,b"
    payload = bytes([20]) + b"\x00" * 16 + struct.pack(">I", 3) + b"a,b"
    lists = _parse_kexinit(payload)
    assert lists and lists[0] == ["a", "b"], lists
    # exposed service mapping
    f = exposed_service_finding("10.0.0.1", 9200)
    assert f and "Elasticsearch" in f["vulnerability"]
    assert exposed_service_finding("10.0.0.1", 80) is None
    print("scanner_checks self-tests passed")
