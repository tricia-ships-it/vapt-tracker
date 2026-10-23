# VAPT Tracker

A self-contained, **offline** vulnerability assessment and remediation-tracking
platform for quarterly data-centre VAPT work. It runs entirely on an internal
network — no internet, no AI, no telemetry, no data leaves the machine.

It does three jobs:

1. **Assess** — a built-in scanner probes targets locally (host discovery, open
   ports, service/version fingerprinting, TLS/SSL checks, HTTP security-header
   review, and known-CVE matching). It also imports results from Nessus,
   OpenVAS/Greenbone and Nmap to corroborate with trusted engines.
2. **Track & report** — every finding is classified, given a target fix date, and
   tracked through remediation, with automated Actual Risk, Target Fix Date, Time
   to Fix and Risk Tolerance Objective. Exports to Excel (live formulas) and PDF.
3. **Collaborate** — the whole team signs in with individual accounts, sees the
   same register, comments on findings, and watches an activity feed. Hosted on
   the intranet, reachable by IP from any browser inside the network.

> **Scope.** This performs *vulnerability assessment* — it identifies and
> reports. It does **not** exploit, brute-force, or alter targets. Penetration
> testing is done manually, by design.

## Repository layout

| Path | What it is |
|---|---|
| `app/` | The Flask application (runs the whole platform). See `app/README.md` for full setup, roles, and deployment. |
| `template/` | `build_template.py` generates the standalone Excel report template (same columns and automation as the app, usable without it). |
| `preview/` | `vapt_preview.html` — a single-file interactive preview of the UI for walkthroughs and demos (no backend; data resets on refresh). |

## Quick start

```bash
cd app
pip install -r requirements.txt
python app.py --host 0.0.0.0 --port 8080
```

On first run the app prints a one-time `admin` password to the console. Sign in,
set a new password, then create team accounts under **Users**. Full instructions,
including the account roles and the recommendation to front it with HTTPS, are in
[`app/README.md`](app/README.md).

To generate just the Excel template:

```bash
cd template
pip install openpyxl
python build_template.py   # writes VAPT_Report_Template.xlsx
```

## Security & data

- `app/vapt.db` (findings, users, comments, activity) and `app/.secret_key`
  (session signing) are created at runtime and are **git-ignored** — they never
  leave the host.
- Passwords are hashed with PBKDF2 (via Werkzeug). Serve behind HTTPS on anything
  wider than a trusted internal segment.

## Responsible use

This is a vulnerability-assessment tool. **Only scan systems you own or are
explicitly authorised to assess.** Scanning networks without permission may be
illegal in your jurisdiction. The software is provided as-is, with no warranty
(see `LICENSE`).

## Licence

Released under the [MIT License](LICENSE) — free to use, modify, and deploy in
your own network. Attribution is welcome. If it's useful to you, a star or a note
back is appreciated.
