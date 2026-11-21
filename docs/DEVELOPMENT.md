# Development guide

Argus is a self-hosted, **offline-first** vulnerability-assessment and
security-awareness platform for internal and data-centre environments. It runs
entirely on the operator's own machine; nothing about their estate leaves it.

This guide orients a developer working in the repo. Read it before making
changes.

## Run it

```bash
cd app
pip install -r requirements.txt
python app.py --host 0.0.0.0 --port 8080        # dev server
# or, production (single process):
waitress-serve --listen=0.0.0.0:8080 wsgi:app
```

First run prints a one-time `admin` password to the console. The SQLite DB and
`.secret_key` are created at runtime (git-ignored).

## Layout

```
app/
  app.py            # Flask app: routes, init_db (schema + migrations), CSRF, helpers
  auth.py           # users, sessions, roles, decorators, activity log
  scanner.py        # assessment-only scanner engine (detection, never exploitation)
  scanner_checks.py # individual protocol checks (TLS/SSH/SMB/RDP/HTTP)
  asset_classify.py # asset inventory import + OT scan-governance interlock
  compliance.py     # finding -> control mapping across frameworks
  threatintel.py    # FETCH-ONLY feed sync + local matching (no asset egress)
  feedsync.py       # standalone air-gap feed downloader
  phishing.py       # awareness templates + personalisation (pure)
  delivery.py       # multi-channel transport (SMTP email, Twilio SMS/WhatsApp)
  sending.py        # durable, paced, crash-safe background send jobs + worker
  export_excel.py / export_pdf.py
  templates/ static/
docs/               # design notes — docs/phishing-delivery.md is the deep one
```

## Conventions

- **One file, server-rendered.** Jinja templates extend `base.html`; styles live
  in `static/style.css` (dark-first CSS custom properties, light theme via
  `:root[data-theme=light]`). No build step, no JS framework; charts are
  hand-drawn SVG in `static/charts.js`.
- **CSRF**: every state-changing form posts a hidden `name="_csrf"`
  (`{{ csrf_token() }}`); AJAX posts send `X-CSRF-Token`. Enforced globally in
  `_csrf_protect()`. GET is exempt.
- **Auth**: roles are `admin`, `editor`, `viewer`. Decorate routes with
  `@auth.login_required` or `@auth.role_required("admin","editor")`. Management
  mutations are editor/admin; `can_import_or_scan()` is the editor/admin gate.
- **DB**: SQLite via `get_db()` (request-scoped). Schema is created idempotently
  in `init_db()`, which also runs lightweight `ALTER TABLE` migrations for new
  columns — add new columns there, not by assuming a fresh DB. WAL is on.
- **Tests**: each core module self-tests when run directly:

  ```bash
  cd app
  for m in phishing delivery sending scanner_checks asset_classify compliance; do
    echo "== $m =="; python3 $m.py || echo "FAILED: $m";
  done
  ```

  Run them after touching those modules.
- Keep diffs minimal and in the app's existing style; prefer editing the
  `init_db` migrations over schema rewrites.

## Security invariants — do not regress

These are the whole point of the product. A change that breaks one is a bug even
if it passes tests.

- **Scanner is assessment-only.** Detection and fingerprinting, never
  exploitation, brute force, or payload delivery.
- **OT governance.** Assets classified OT are marked "do not actively scan"; the
  scanner must skip blocklisted hosts and log the skip.
- **Threat intel is fetch-only.** Feeds are pulled from a visible allowlist;
  asset inventory never leaves the machine; matching is local. No code path may
  POST/PUT asset data anywhere.
- **Phishing is awareness-only.** No credential capture, no fake login pages. The
  teachable landing page has no form. See `docs/phishing-delivery.md` for the
  full invariant list (gated sending, env-only secrets, no social auto-DM, etc.).
- **Secrets from environment only** — SMTP/Twilio credentials are read from env
  vars, never entered in the UI or stored in the DB.
- **No impersonation.** Simulated templates use generic roles and `.example`
  domains, never a real company, brand, or person.
