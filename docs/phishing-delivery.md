# Phishing awareness & delivery — design notes

This document is the "thinking" behind Argus's phishing-awareness feature: what
it is, the decisions that shaped it, the threat model, and what is deliberately
*not* built. Read it before extending the feature so the guardrails survive.

## What the feature is for

Let a security team run **simulated** phishing exercises against **their own
staff**, measure who clicks, and turn each click into a teachable moment so
people get better at spotting the real thing. It is an awareness tool, not an
attack tool.

The whole design turns on one fact: the *mechanism* of an awareness drill
(personalised message + tracked link + send to a list) is identical to the
mechanism of spam/phishing. The only thing that makes it legitimate is that the
targets are your own authorised staff. Every guardrail below exists to keep that
line bright.

## Modules

| File | Responsibility |
|------|----------------|
| `phishing.py` | Awareness email templates + personalisation + program stats. Pure, no I/O. |
| `delivery.py` | Multi-channel transport: first-name extraction, per-channel render, SMTP (email) and Twilio (SMS/WhatsApp) providers, env-based config. Transport-injectable. |
| `sending.py` | Durable, paced, crash-safe background send jobs + the worker thread. |
| `app.py` | Routes, auth, CSRF, the campaign/recipient/landing/job endpoints. |

Templates: `phishing.html` (program dashboard), `phishing_new.html` (create),
`phishing_campaign.html` (detail + send controls + live progress),
`phishing_landing.html` (public teachable page).

## Hard invariants (do not regress)

1. **No credential capture, ever.** The tracked link leads to a teachable page
   with *no form and no password field*. Argus must never host a fake login.
   A test asserts the landing page renders zero `<input>` elements.
2. **Argus is not the sending engine.** It formats `{message + personal tracked
   link}` and hands off to a provider the organisation controls (their SMTP,
   their Twilio). Transport lives in `delivery.py` behind injectable providers.
3. **Provider secrets come from the environment only** — never the web UI, never
   the database. A compromised admin session cannot read them; they never land
   in DB backups. Settings shows configured/not status and the variable names.
4. **Sending is gated.** A campaign must be `Active`, explicitly `authorized`
   (a human attestation that these recipients may be tested), and the channel's
   provider configured. Only recipients attached to *that* campaign are ever
   contacted — there is no "send to an arbitrary list" path.
5. **Opaque tokens.** Per-recipient tracking tokens are `secrets.token_urlsafe`;
   no name, email or id is encoded in the URL.
6. **Templates never impersonate a real brand or person** — generic role framing
   (IT Service Desk, HR) with `.example` domains.
7. **Social handles are never auto-messaged.** There is no sanctioned API for
   unsolicited DMs and it breaks platform terms. Argus prepares the message +
   link for manual sending only (the "Copy message" button).

## The send engine (`sending.py`)

Sending a drill to a real staff list must not happen inside a web request — it
would time out, show no progress, lose its place on a crash, and hammer the
provider. So a send is a **durable job**:

- A row in `phish_send_job` tracks `status`, `total`, `processed`, `ok_count`,
  `fail_count`, `rate_per_min`, `scheduled_at`, `base_url`.
- A single background worker thread (started lazily on first send, and at app
  boot to resume) processes one job at a time.
- **Paced** to `rate_per_min` (default 30) so the provider stays happy.
- **Progress committed after every message**, so the UI shows a live bar and a
  crash leaves an *exactly resumable* job.
- **Idempotent**: a recipient with `sent_at` set is skipped, so resuming or
  re-queuing never double-sends.
- **Gate re-check at run time**: a job for a campaign that was closed or
  de-authorised after queuing fails without sending.
- **Schedulable** (`scheduled_at`) and **cancellable** (cooperative, checked
  each message).
- **Crash recovery**: on boot, a job left `running`/`canceling` is requeued.

SQLite runs in WAL mode with a busy timeout so the worker writes progress while
web requests read, without lock contention.

### Scaling caveat

One in-process worker suits a self-hosted, single-process deployment. Running
multiple web workers (e.g. `gunicorn -w 4`) would start one worker *each*. For
that scale, move job claiming to an external queue (or add a DB row-lock /
`SELECT ... FOR UPDATE`-style claim) so only one process runs a given job. The
idempotency (skip `sent_at`) already makes accidental double-processing safe,
but pacing would be per-worker.

## Channels

| Channel | Status | Notes |
|---------|--------|-------|
| Email (SMTP) | built | The solid core. `ARGUS_SMTP_*`. |
| SMS (Twilio) | built | `ARGUS_TWILIO_SID/TOKEN/FROM`. |
| WhatsApp (Twilio) | built, best-effort | Meta only delivers approved templates; lure content is usually rejected. `ARGUS_TWILIO_WA_FROM`. |
| Voice | documented hook | Not automated — higher risk, needs a per-campaign script. |
| Social | manual only | Prepared for hand-sending; never auto-messaged. |

Environment variables are listed on the Settings page and in `delivery.py`.

## Roadmap (ordered by value)

1. **Delivery-result callbacks** — capture Twilio status callbacks and SMTP
   bounces so `delivery_status` reflects true delivery, not just hand-off.
   Needs a public callback route authenticated by a per-message signed id.
2. **Repeat-clicker & department analytics** — trend click-rate across
   campaigns, flag repeat clickers for targeted follow-up training.
3. **Template management UI** — let admins create/edit templates (currently
   code-only in `phishing.py`); keep the no-real-brand rule enforced.
4. **Per-template landing pages** — tailor the teachable content to each lure.
5. **Open tracking (email pixel)** — optional, with a clear privacy note.
6. **CSV/Excel recipient import** — reuse the asset-inventory importer.
7. **Worker hardening for multi-process** — see scaling caveat above.

## Test coverage

- `python3 phishing.py` — templates, personalisation.
- `python3 delivery.py` — first-name extraction, render, SMTP via fake
  transport, Twilio SMS/WhatsApp via fake HTTP, dispatch routing.
- `python3 sending.py` — pacing, idempotency, gate re-check, mid-flight cancel,
  crash recovery.
- Flask-client tests exercise the authorize gate, job creation, duplicate
  refusal, progress polling, scheduling and cancel (see `scripts/` test notes).
