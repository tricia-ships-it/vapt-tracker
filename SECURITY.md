# Security

This document records the security review of VAPT Tracker, the controls built
in, and the operational hardening you should apply when deploying it.

## Self-assessment summary

The application was source-reviewed (SAST-style) covering authentication,
authorization, injection, XSS, CSRF, SSRF/command execution, session handling,
file uploads and secrets. Findings were remediated in-code; the controls below
are what ship in this repository.

## Controls built in

**Authentication & sessions**
- Passwords hashed with PBKDF2 (Werkzeug `generate_password_hash`); never stored
  or logged in clear.
- Session cookies set `HttpOnly` and `SameSite=Lax`. `Secure` is enabled when you
  set the `VAPT_HTTPS=1` environment variable (do this behind TLS).
- Session-signing key is generated once and stored in `app/.secret_key`
  (mode 600, git-ignored).
- 12-hour session lifetime.
- Login throttling: an IP is locked out after 8 failed attempts within 5 minutes.
- Generic login error messages (no username enumeration).

**Authorization (roles)**
- Three roles enforced server-side on every route: `admin`, `editor`, `viewer`.
- Viewers can view and comment everywhere, and may update the remediation
  progress of findings **they own** (status, fix/exception dates and comments)
  but cannot change a finding's classification, ownership or vulnerability
  details, nor import, scan, or manage users.

**Web attack surface**
- CSRF: a session-bound token is required on every state-changing request
  (forms and the JSON/fetch endpoints via the `X-CSRF-Token` header).
- XSS: all output is rendered through Jinja2 autoescaping; exports HTML-escape
  every field. No `render_template_string` or `|safe` on user data.
- SQL injection: all queries are parameterized; column names are never taken
  from user input.
- Open redirect: the login `next` parameter accepts only same-site relative
  paths.
- Security headers on every response: `Content-Security-Policy` (self-only),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`.
- Uploads capped at 64 MB.

**Scan input parsing**
- Uploaded XML is rejected if it contains a `DOCTYPE` or `ENTITY` declaration
  (defence against entity-expansion / "billion laughs" denial of service). The
  stdlib parser does not resolve external entities, so XXE file disclosure is
  not possible.

**The scanner itself**
- Assessment only: it identifies and reports. It does not run exploits,
  brute-force credentials, or alter targets. Scanning is restricted to editors
  and admins. Ping uses a fixed argument list (no shell), and targets are
  validated as IPs/CIDR/ranges before use — no command injection.

## Dependency security

Runtime dependencies are **pinned to exact versions** in `app/requirements.txt`
(Flask, openpyxl, and optionally reportlab; Flask pulls in Werkzeug, Jinja2,
MarkupSafe, itsdangerous, click and blinker). Pinning keeps installs predictable
and makes audits meaningful.

**Audit for known CVEs** — run before deploying and periodically after:

```bash
./scripts/audit.sh            # Linux / macOS
powershell -ExecutionPolicy Bypass -File scripts\audit.ps1   # Windows
```

Both wrap [`pip-audit`](https://pypi.org/project/pip-audit/), which checks your
installed packages against the PyPI Advisory and OSV databases. If it flags a
package, bump its pin in `app/requirements.txt` and re-run.

**Reproducible, hash-verified installs (recommended for production).** Generate a
lock on your target platform so every install is byte-for-byte verified — this is
done on your machine rather than shipped, because wheel hashes are
platform-specific:

```bash
pip install pip-tools
pip-compile --generate-hashes --output-file=app/requirements.lock app/requirements.txt
pip install --require-hashes -r app/requirements.lock
```

The air-gapped install flow (wheel cache) in `app/README.md` works the same way
with `--require-hashes` added.

## Operational hardening (your responsibility when deploying)

1. **Serve behind HTTPS.** The app speaks plain HTTP by default, which is fine on
   a trusted, isolated segment, but because people log in with passwords you
   should terminate TLS in front of it (nginx, Caddy, IIS/ARR) using a
   certificate from your internal CA, and set `VAPT_HTTPS=1` so the session
   cookie is marked `Secure`.
2. **Restrict network exposure.** Bind it to the management VLAN and firewall it
   so only intended staff can reach the port. It is designed for an internal
   network and makes no outbound internet connections.
3. **Never run with `--debug` on a reachable interface.** The Werkzeug debugger
   allows code execution. Debug is off by default; keep it off in deployment.
4. **Use a production WSGI server** (e.g. `waitress-serve --host <ip> --port 8080
   app:app`) rather than the Flask development server.
5. **Back up `app/vapt.db`** (your findings, users, comments and history) and keep
   `app/.secret_key` private.
6. **Only scan systems you are authorised to assess.**

## Reporting a vulnerability

If you find a security issue in this tool, please open a GitHub issue (or contact
the maintainer privately for anything sensitive) rather than disclosing it
publicly before it can be fixed.
