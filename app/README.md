# VAPT Assessment & Remediation Tracker

A self-contained, **offline** vulnerability assessment and remediation-tracking
platform for quarterly data-centre VAPT work. It runs entirely on your internal
network — no internet, no AI, no telemetry, no data leaves the machine.

It does two jobs:

1. **Assess** — a built-in scanner probes your targets locally (discovery, open
   ports, service/version fingerprinting, TLS/SSL checks, HTTP security-header
   review, and known-CVE matching). It also **imports** results from Nessus,
   OpenVAS/Greenbone and Nmap so you can corroborate with your trusted engines.
2. **Track & report** — every finding is classified, given a target fix date,
   and tracked through remediation, with your exact report structure and all the
   automation (Actual Risk, Target Fix Date, Risk Tolerance Objective, etc.).
   Exports to Excel (live formulas) and PDF.
3. **Collaborate** — your whole team signs in with individual accounts, sees the
   same register, comments on findings, and watches an activity feed of what's
   changed. Hosted on your intranet; reachable by IP from any browser inside the
   network.

> **Scope note.** This tool performs *vulnerability assessment* — it identifies
> and reports. It does **not** exploit, brute-force, or alter targets.
> Penetration testing is done manually by your team, by design. See
> "What the scanner does and doesn't do" below.

---

## 1. Install (one time)

On a machine with Python 3.9+:

```bash
pip install -r requirements.txt
```

`Flask` and `openpyxl` are required. `reportlab` is optional — without it, PDF
export produces a print-ready HTML page instead (use your browser's *Print →
Save as PDF*).

**Air-gapped install.** On a machine with no internet, build an offline wheel
cache on a connected machine first:

```bash
# on a connected machine
pip download -r requirements.txt -d wheels/
# copy the whole folder across, then on the offline machine:
pip install --no-index --find-links wheels/ -r requirements.txt
```

The application code itself uses only the Python standard library plus Flask and
openpyxl — nothing else is fetched at runtime.

## 2. Run

```bash
python app.py                      # http://127.0.0.1:5000 (this machine only)
python app.py --host 10.0.0.5 --port 8080   # expose to the internal network
```

Bind to the machine's intranet address (`--host`) so colleagues can reach it at
`http://<that-ip>:<port>/` from anywhere inside your network.

Data is stored in `vapt.db` (SQLite) next to `app.py`. Back that file up to keep
your register, accounts, comments and activity. A `.secret_key` file is created
next to it to sign login sessions — keep it (don't commit it anywhere public);
deleting it just logs everyone out. To start completely fresh, stop the app and
delete both `vapt.db` and `.secret_key`.

For a team, run it behind a production WSGI server
(e.g. `pip install waitress` then
`waitress-serve --host 10.0.0.5 --port 8080 app:app`) rather than the built-in
Flask dev server.

### First run: the admin account

The first time the app starts it creates an **admin** account and prints a
one-time password to the console:

```
================================================================
  FIRST RUN — an administrator account has been created.
    Username: admin
    One-time password: <shown here>
================================================================
```

Sign in as `admin`, set a new password when prompted, then open **Users** to
create accounts for your team.

## 2a. Accounts and roles

Everyone logs in with their own username and password (passwords are hashed with
PBKDF2; never stored in the clear). An admin creates all accounts under **Users**
and assigns one of three roles:

| Role | Can do |
|---|---|
| **Admin** | Everything, plus manage user accounts |
| **Editor** (security team) | Import, scan, add/edit findings, change any status, manage asset owners, comment |
| **Viewer** (bosses, colleagues, asset owners) | See everything, comment, and change the status of findings **they own** |

"Owns" means the finding's **Asset Owner** matches the viewer's account display
name (or username). So you can let an asset owner self-report progress on their
own systems without giving them edit rights across the whole register. (This is
the "Editors plus asset owners" model.)

Admins can deactivate an account (blocks sign-in, keeps their history) or reset a
password (the user must then choose a new one at next sign-in).

### Security note — put it behind HTTPS

By default the app serves plain HTTP, which is fine on a trusted internal
segment. Because people log in with passwords, for anything wider you should
terminate **HTTPS** in front of it — e.g. an internal reverse proxy (nginx,
Caddy, IIS/ARR) with a certificate from your internal CA — and restrict access to
the management VLAN by firewall. The app never reaches the internet either way.

## 3. Use

**Run scan** — enter target IPs, ranges (`10.0.0.1-20`) or CIDR (`10.0.0.0/24`),
pick your ports, and start. Progress streams live; when it finishes, review the
count and click **Add findings to register**.

**Import scan** — upload `.nessus`, Nessus CSV, OpenVAS XML/CSV, or Nmap `-oX`
XML. The register fills itself (severity, CVEs, synopsis, solution).

**Findings** — the register. Change a status inline (Actual Fix Date stamps
itself for *Fixed* / *Not Applicable*, and Risk Tolerance recalculates). Open any
finding to edit every field, set asset criticality, raise an exception, or add
owner comments.

**Discussion** — every finding has a comment thread. Anyone with access can post;
each comment is stamped with who wrote it and when, and shows up in the activity
feed. Use it for questions, remediation updates, and decisions.

**Activity** — a running feed of everything that's changed (status updates,
comments, imports, scans, new accounts) so anyone returning to the tool can see
what's new since they last looked.

**Export** — Excel (with live formulas) or PDF, any time.

---

## What the scanner does and doesn't do

**Does (non-destructive assessment):**

- Host discovery (ping and/or TCP probe)
- TCP port scan across your chosen ports
- Service + version banner grab (SSH, HTTP, FTP, SMTP, …)
- TLS/SSL checks: deprecated protocol support (TLS 1.0/1.1), untrusted /
  expired / self-signed certificates
- HTTP security-header review (missing HSTS, CSP, X-Frame-Options, …) and
  server version disclosure
- Risky-service flags (Telnet, exposed Redis/Memcached/NFS/SNMP, …)
- Version → CVE matching against the **local** dataset (`vuln_db.py`)

**Does not:**

- Send exploit payloads, run exploit modules, or achieve code execution
- Brute-force or test credentials
- Modify, delete, or disrupt anything on the target

It makes the same benign connections any ordinary client makes. **Only scan
systems you are authorised to assess.**

### Keeping CVE coverage current

The built-in scanner matches against a curated **local** dataset of high-impact
infrastructure CVEs and EOL rules (`vuln_db.py`) so it works offline. This is
**not** a substitute for a maintained feed. For authoritative, always-current
coverage, run **Nessus or OpenVAS** (tens of thousands of maintained checks) and
import their results — the two approaches corroborate each other.

Extend the local dataset by editing `VERSION_RULES` / `EOL_RULES` in
`vuln_db.py`, or load an updated JSON offline with `vuln_db.load_external(path)`.

---

## The automation rules (single source of truth: `engine.py`)

These are applied identically in the app and in the exported Excel, so both
agree to the day.

**Actual Risk Classification** — looked up from
`Asset Classification × Reported Risk Rating × Exploit Available` using the
60-row matrix (the same logic as your original `XLOOKUP`, re-expressed as
`INDEX/MATCH` so it's reliable in Excel *and* LibreOffice).

**Target Fix Date** — `Detection Date + SLA`:

| Actual Risk | SLA |
|---|---|
| Critical | +30 days |
| High | +60 days |
| Medium | +90 days |
| Low | +120 days |
| Information | none (discretionary) |

**Time to Fix (Days)** — the SLA window (`Target Fix Date − Detection Date`).

**Actual Fix Date** — auto-stamped the day a finding is set to *Fixed* or
*Not Applicable*; remains editable (set it to the real date if it was fixed
earlier).

**Risk Tolerance Objective** —
*Met* if the Actual Fix Date is on/before the effective target (the Revised
Target Fix Date when an exception was approved, otherwise the Target Fix Date);
*Breached* if later; *Not Applicable* when the status is *Not Applicable*,
*Risk Accepted*, or *Exception Approved*.

**Remediation statuses** — Pending, Reported, In progress, On hold, Testing,
Fixed, Not Applicable, Risk Accepted, Exception Approved.

---

## Report columns

IP / Hostname · Device · Asset Classification · Vulnerability · Synopsis ·
Definition · CVE · Risk Statement · Reported Risk Rating · Exploit Available ·
**Actual Risk Classification** · Exploit Reference · Solution · Asset Owner ·
Detection Date · **Target Fix Date** · **Time to Fix (Days)** · Remediation
Status · Actual Fix Date · **Risk Tolerance Objective** · Exception Requested? ·
Exception Approved By · Revised Target Fix Date · Asset Owner's Comment · Comment

(**bold** = calculated automatically.)

---

## Files

| File | Purpose |
|---|---|
| `app.py` | Flask application (routes, DB, serving) |
| `auth.py` | User accounts, roles, password hashing, sessions, permissions |
| `engine.py` | Risk matrix, fix-window and risk-tolerance logic — the single source of truth |
| `scanner.py` | Built-in offline vulnerability scanner |
| `vuln_db.py` | Local CVE / EOL dataset and matcher |
| `parsers/` | Nessus, OpenVAS and Nmap importers |
| `export_excel.py` / `export_pdf.py` | Report exporters |
| `templates/`, `static/` | Web UI |
| `sample_scans/` | Example scan files to try the importers |
| `vapt.db` | Your data: findings, users, comments, activity (created on first run) |
| `.secret_key` | Session-signing key (created on first run; keep it private) |

## Quick test with the samples

Start the app, go to **Import scan**, and upload any file from `sample_scans/`
to see findings flow into the register with full automation. Then try **Run
scan** against a host you're authorised to assess.
